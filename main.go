package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ecomm-micro-org/auth-service/cache"
	"github.com/ecomm-micro-org/auth-service/db"
	"github.com/ecomm-micro-org/auth-service/handlers"
	"github.com/ecomm-micro-org/auth-service/interceptors"
	"github.com/ecomm-micro-org/auth-service/internal/token"
	"github.com/ecomm-micro-org/auth-service/pb"
	"github.com/ecomm-micro-org/auth-service/services"
	"github.com/ecomm-micro-org/auth-service/store"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	db.Connect()
	db.AutoMigrate()
	cache.Connect()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	secretKey, ok := os.LookupEnv("SECRET_KEY")
	if !ok {
		log.Fatalf("secret key not defined\n")
	}
	issuer, ok := os.LookupEnv("ISSUER")
	if !ok {
		log.Fatalf("issuer not defined")
	}

	s := store.NewPGStore(db.Client())
	jm := token.NewJWTMaker(secretKey, issuer)
	svc := services.NewAuthService(s, jm)

	grpcServer, err := createGRPCServer(svc)
	if err != nil {
		log.Fatalf("unable to create the server : %v\n", err)
	}

	if err := runGRPCServer(context.Background(), grpcServer); err != nil {
		log.Fatalf("unable to start the server : %v", err)
	}

	if err := db.Disconnect(); err != nil {
		log.Printf("couldnt disconnect from db : %v\n", err)
	}
	log.Println("db disconnected successfully")
}

func createGRPCServer(svc *services.AuthService) (*grpc.Server, error) {
	l, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	li := interceptors.NewLoggingInterceptor(l)

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(li.UnaryLoggingInterceptor()),
	)

	pb.RegisterAuthServiceServer(grpcServer, handlers.NewAuthHandler(svc))

	return grpcServer, nil
}

func runGRPCServer(ctx context.Context, grpcServer *grpc.Server) error {
	serverErr := make(chan error, 1)

	go func() {
		log.Println("auth service running on port :6969")
		lis, err := net.Listen("tcp", ":6969")
		if err != nil {
			log.Fatalf("unable to listen on port :6969\n")
		}

		if err := grpcServer.Serve(lis); !errors.Is(err, grpc.ErrServerStopped) {
			serverErr <- err
		}
		close(serverErr)
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case <-shutdown:
		log.Println("shutdown signal received")
	case <-ctx.Done():
		log.Println("parent context cancelled")
	}

	grpcServer.GracefulStop()

	log.Println("sever exited successfully")
	return nil
}
