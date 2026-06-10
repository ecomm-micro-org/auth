package services

import (
	"fmt"
	"time"

	"github.com/ecomm-micro-org/auth-service/internal/token"
	"github.com/ecomm-micro-org/auth-service/models"
	"github.com/ecomm-micro-org/auth-service/pb"
	"github.com/ecomm-micro-org/auth-service/store"
	"github.com/ecomm-micro-org/auth-service/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthService struct {
	store      store.Storer
	tokenMaker *token.JWTMaker
}

func NewAuthService(store store.Storer, tokenMaker *token.JWTMaker) *AuthService {
	return &AuthService{
		store:      store,
		tokenMaker: tokenMaker,
	}
}

func (s *AuthService) Signin(username, email, password, role, phone, address string) (*pb.SigninResponse, error) {
	m := models.NewUser()
	m.Username = username
	m.Email = email
	m.Role = models.Role(role)
	m.Phone = phone
	m.Address = address

	hashedPassword, err := util.HashPassword(password)
	if err != nil {
		return nil, err
	}

	m.Password = hashedPassword

	if err := s.store.AddUser(m); err != nil {
		return nil, err
	}

	//generate JWT token and return
	accessToken, accessTokenClaims, err := s.tokenMaker.CreateToken(m.ID, m.Email, m.Role.String(), 15*time.Minute)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshTokenClaims, err := s.tokenMaker.CreateToken(m.ID, m.Email, m.Role.String(), 24*time.Hour)
	if err != nil {
		return nil, err
	}

	sess := models.NewSession()
	sess.ID = refreshTokenClaims.RegisteredClaims.ID
	sess.UserEmail = m.Email
	sess.RefreshToken = refreshToken
	sess.IsRevoked = false
	sess.ExpiresAt = refreshTokenClaims.ExpiresAt.Time

	if err := s.store.CreateSession(sess); err != nil {
		return nil, err
	}

	res := &pb.SigninResponse{}
	res.SessionId = sess.ID
	res.AccessToken = accessToken
	res.AccessTokenExpiresAt = timestamppb.New(accessTokenClaims.ExpiresAt.Time)
	res.RefreshToken = refreshToken
	res.RefreshTokenExpiresAt = timestamppb.New(accessTokenClaims.ExpiresAt.Time)
	res.User = &pb.User{
		Id:        m.ID.String(),
		Username:  m.Username,
		Email:     m.Email,
		Role:      m.Role.String(),
		Address:   m.Address,
		Phone:     m.Phone,
		CreatedAt: timestamppb.New(m.CreatedAt),
		UpdatedAt: timestamppb.New(m.UpdatedAt),
		DeletedAt: timestamppb.New(m.DeletedAt),
	}

	return res, nil
}

func (s *AuthService) Login(email, password string) (*pb.LoginResponse, error) {
	u := models.NewUser()
	err := s.store.GetUserByEmail(u, email)
	if err != nil {
		return nil, err
	}

	if err := util.CheckPassword(password, u.Password); err != nil {
		return nil, err
	}

	//generate JWT token and return
	accessToken, accessTokenClaims, err := s.tokenMaker.CreateToken(u.ID, u.Email, u.Role.String(), 15*time.Minute)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshTokenClaims, err := s.tokenMaker.CreateToken(u.ID, u.Email, u.Role.String(), 24*time.Hour)
	if err != nil {
		return nil, err
	}

	sess := models.NewSession()
	sess.ID = refreshTokenClaims.RegisteredClaims.ID
	sess.UserEmail = u.Email
	sess.RefreshToken = refreshToken
	sess.IsRevoked = false
	sess.ExpiresAt = refreshTokenClaims.ExpiresAt.Time

	if err := s.store.CreateSession(sess); err != nil {
		return nil, err
	}

	res := &pb.LoginResponse{}
	res.SessionId = sess.ID
	res.AccessToken = accessToken
	res.AccessTokenExpiresAt = timestamppb.New(accessTokenClaims.ExpiresAt.Time)
	res.RefreshToken = refreshToken
	res.RefreshTokenExpiresAt = timestamppb.New(accessTokenClaims.ExpiresAt.Time)
	res.User = &pb.User{
		Id:        u.ID.String(),
		Username:  u.Username,
		Email:     u.Email,
		Role:      u.Role.String(),
		Address:   u.Address,
		Phone:     u.Phone,
		CreatedAt: timestamppb.New(u.CreatedAt),
		UpdatedAt: timestamppb.New(u.UpdatedAt),
		DeletedAt: timestamppb.New(u.DeletedAt),
	}

	return res, nil
}

func (s *AuthService) Logout(sessionID string) error {
	sess := models.NewSession()
	sess.ID = sessionID

	if err := s.store.GetSession(sess); err != nil {
		return err
	}

	if err := s.store.DeleteSession(sess); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) RenewAccessToken(refreshToken string) (*pb.RenewAccessTokenResponse, error) {
	refreshTokenClaims, err := s.tokenMaker.VerifyToken(refreshToken)
	if err != nil {
		return nil, err
	}

	sess := models.NewSession()
	sess.ID = refreshTokenClaims.RegisteredClaims.ID
	if err := s.store.GetSession(sess); err != nil {
		return nil, err
	}

	if sess.IsRevoked {
		return nil, fmt.Errorf("session is revoked")
	}

	if sess.UserEmail != refreshTokenClaims.Email {
		return nil, fmt.Errorf("invalid token, email does not match")
	}

	accessToken, accessTokenClaims, err := s.tokenMaker.CreateToken(refreshTokenClaims.ID, refreshTokenClaims.Email, refreshTokenClaims.Role, 15*time.Minute)
	if err != nil {
		return nil, err
	}

	res := &pb.RenewAccessTokenResponse{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: timestamppb.New(accessTokenClaims.ExpiresAt.Time),
	}

	return res, nil
}

func (s *AuthService) RevokeSession(sessionID string) error {
	sess := models.NewSession()
	sess.ID = sessionID
	if err := s.store.GetSession(sess); err != nil {
		return err
	}

	if err := s.store.RevokeSession(sess); err != nil {
		return err
	}
	return nil
}
