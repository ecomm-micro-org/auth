package handlers

import (
	"context"
	"errors"

	"github.com/ecomm-micro-org/auth-service/pb"
	"github.com/ecomm-micro-org/auth-service/services"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"
)

type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	svc *services.AuthService
}

func NewAuthHandler(svc *services.AuthService) *AuthHandler {
	return &AuthHandler{
		svc: svc,
	}
}
func (h *AuthHandler) Signin(ctx context.Context, req *pb.SigninRequest) (*pb.SigninResponse, error) {
	res, err := h.svc.Signin(req.Username, req.Email, req.Password, req.Role, req.Phone, req.Address)
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "something went wrong")
	}
	return res, nil
}

func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	res, err := h.svc.Login(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "something went wrong")
	}
	return res, nil
}

func (h *AuthHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*emptypb.Empty, error) {
	if err := h.svc.Logout(req.SessionId); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		return nil, status.Error(codes.Internal, "something went wrong")
	}
	return &emptypb.Empty{}, nil
}

func (h *AuthHandler) RenewAccessToken(ctx context.Context, req *pb.RenewAccessTokenRequest) (*pb.RenewAccessTokenResponse, error) {
	res, err := h.svc.RenewAccessToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}
	return res, nil
}

func (h *AuthHandler) RevokeSession(ctx context.Context, req *pb.RevokeSessionReqeust) (*emptypb.Empty, error) {
	if err := h.svc.RevokeSession(req.SessionId); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		return nil, status.Error(codes.Internal, "something went wrong")
	}
	return &emptypb.Empty{}, nil
}
