package handlers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ecomm-micro-org/auth-service/handlers"
	"github.com/ecomm-micro-org/auth-service/internal/token"
	"github.com/ecomm-micro-org/auth-service/models"
	"github.com/ecomm-micro-org/auth-service/pb"
	"github.com/ecomm-micro-org/auth-service/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

const (
	handlerTestSecret = "test-secret-key-that-is-long-enough"
	handlerTestIssuer = "test-issuer"
)

// ---------------------------------------------------------------------------
// stubStore — injectable test double for store.Storer
// ---------------------------------------------------------------------------

type stubStore struct {
	addUserErr error

	getUserErr    error
	getUserResult *models.User

	createSessionErr error

	getSessionErr    error
	getSessionResult *models.Session

	revokeSessionErr error
	deleteSessionErr error
}

func (s *stubStore) AddUser(_ *models.User) error { return s.addUserErr }

func (s *stubStore) GetUserByEmail(u *models.User, _ string) error {
	if s.getUserErr != nil {
		return s.getUserErr
	}
	if s.getUserResult != nil {
		*u = *s.getUserResult
	}
	return nil
}

func (s *stubStore) CreateSession(_ *models.Session) error { return s.createSessionErr }

func (s *stubStore) GetSession(dst *models.Session) error {
	if s.getSessionErr != nil {
		return s.getSessionErr
	}
	if s.getSessionResult != nil {
		*dst = *s.getSessionResult
	}
	return nil
}

func (s *stubStore) RevokeSession(_ *models.Session) error { return s.revokeSessionErr }
func (s *stubStore) DeleteSession(_ *models.Session) error { return s.deleteSessionErr }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestHandler(st *stubStore) *handlers.AuthHandler {
	maker := token.NewJWTMaker(handlerTestSecret, handlerTestIssuer)
	svc := services.NewAuthService(st, maker)
	return handlers.NewAuthHandler(svc)
}

func mustHashPassword(t *testing.T, pw string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

func mintRefreshToken(t *testing.T, id uuid.UUID, email, role string, dur time.Duration) (string, *token.UserClaims) {
	t.Helper()
	maker := token.NewJWTMaker(handlerTestSecret, handlerTestIssuer)
	tok, claims, err := maker.CreateToken(id, email, role, dur)
	require.NoError(t, err)
	return tok, claims
}

func grpcCode(err error) codes.Code {
	s, ok := status.FromError(err)
	if !ok {
		return codes.Unknown
	}
	return s.Code()
}

// ---------------------------------------------------------------------------
// TestAuthHandler_Signin
// ---------------------------------------------------------------------------

func TestAuthHandler_Signin(t *testing.T) {
	tests := []struct {
		name         string
		req          *pb.SigninRequest
		store        *stubStore
		expectedCode codes.Code
		validate     func(t *testing.T, res *pb.SigninResponse)
	}{
		{
			name: "success: returns tokens and user",
			req: &pb.SigninRequest{
				Username: "alice",
				Email:    "alice@test.com",
				Password: "password123",
				Role:     "buyer",
				Phone:    "5551234",
				Address:  "1 Main St",
			},
			store:        &stubStore{},
			expectedCode: codes.OK,
			validate: func(t *testing.T, res *pb.SigninResponse) {
				assert.NotEmpty(t, res.AccessToken)
				assert.NotEmpty(t, res.RefreshToken)
				assert.NotEmpty(t, res.SessionId)
				require.NotNil(t, res.User)
				assert.Equal(t, "alice@test.com", res.User.Email)
				assert.Equal(t, "alice", res.User.Username)
			},
		},
		{
			name: "duplicate user returns AlreadyExists",
			req: &pb.SigninRequest{
				Username: "alice",
				Email:    "alice@test.com",
				Password: "password123",
				Role:     "buyer",
				Phone:    "5551234",
				Address:  "1 Main St",
			},
			store:        &stubStore{addUserErr: gorm.ErrDuplicatedKey},
			expectedCode: codes.AlreadyExists,
		},
		{
			name: "store error returns Internal",
			req: &pb.SigninRequest{
				Username: "bob",
				Email:    "bob@test.com",
				Password: "password123",
				Role:     "buyer",
				Phone:    "5551234",
				Address:  "1 Main St",
			},
			store:        &stubStore{addUserErr: errors.New("db error")},
			expectedCode: codes.Internal,
		},
		{
			name: "CreateSession error returns Internal",
			req: &pb.SigninRequest{
				Username: "carol",
				Email:    "carol@test.com",
				Password: "password123",
				Role:     "buyer",
				Phone:    "5551234",
				Address:  "1 Main St",
			},
			store:        &stubStore{createSessionErr: errors.New("session error")},
			expectedCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(tt.store)
			res, err := h.Signin(context.Background(), tt.req)

			assert.Equal(t, tt.expectedCode, grpcCode(err))

			if tt.expectedCode == codes.OK {
				require.NoError(t, err)
				require.NotNil(t, res)
				if tt.validate != nil {
					tt.validate(t, res)
				}
			} else {
				require.Error(t, err)
				assert.Nil(t, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthHandler_Login
// ---------------------------------------------------------------------------

func TestAuthHandler_Login(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name         string
		req          *pb.LoginRequest
		store        func(t *testing.T) *stubStore
		expectedCode codes.Code
		validate     func(t *testing.T, res *pb.LoginResponse)
	}{
		{
			name:         "success: correct credentials return tokens",
			req:          &pb.LoginRequest{Email: "alice@test.com", Password: "password123"},
			expectedCode: codes.OK,
			store: func(t *testing.T) *stubStore {
				return &stubStore{
					getUserResult: &models.User{
						ID:       userID,
						Username: "alice",
						Email:    "alice@test.com",
						Password: mustHashPassword(t, "password123"),
						Role:     models.Buyer,
					},
				}
			},
			validate: func(t *testing.T, res *pb.LoginResponse) {
				assert.NotEmpty(t, res.AccessToken)
				assert.NotEmpty(t, res.RefreshToken)
				assert.NotEmpty(t, res.SessionId)
			},
		},
		{
			name:         "user not found returns NotFound",
			req:          &pb.LoginRequest{Email: "nobody@test.com", Password: "password123"},
			expectedCode: codes.NotFound,
			store: func(t *testing.T) *stubStore {
				return &stubStore{getUserErr: gorm.ErrRecordNotFound}
			},
		},
		{
			name:         "wrong password returns Unauthenticated",
			req:          &pb.LoginRequest{Email: "alice@test.com", Password: "wrongpassword"},
			expectedCode: codes.Unauthenticated,
			store: func(t *testing.T) *stubStore {
				return &stubStore{
					getUserResult: &models.User{
						ID:       userID,
						Email:    "alice@test.com",
						Password: mustHashPassword(t, "password123"),
						Role:     models.Buyer,
					},
				}
			},
		},
		{
			name:         "store error returns Internal",
			req:          &pb.LoginRequest{Email: "alice@test.com", Password: "password123"},
			expectedCode: codes.Internal,
			store: func(t *testing.T) *stubStore {
				return &stubStore{getUserErr: errors.New("db error")}
			},
		},
		{
			name:         "CreateSession error returns Internal",
			req:          &pb.LoginRequest{Email: "alice@test.com", Password: "password123"},
			expectedCode: codes.Internal,
			store: func(t *testing.T) *stubStore {
				return &stubStore{
					getUserResult: &models.User{
						ID:       userID,
						Email:    "alice@test.com",
						Password: mustHashPassword(t, "password123"),
						Role:     models.Buyer,
					},
					createSessionErr: errors.New("session error"),
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(tt.store(t))
			res, err := h.Login(context.Background(), tt.req)

			assert.Equal(t, tt.expectedCode, grpcCode(err))

			if tt.expectedCode == codes.OK {
				require.NoError(t, err)
				require.NotNil(t, res)
				if tt.validate != nil {
					tt.validate(t, res)
				}
			} else {
				require.Error(t, err)
				assert.Nil(t, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthHandler_Logout
// ---------------------------------------------------------------------------

func TestAuthHandler_Logout(t *testing.T) {
	tests := []struct {
		name         string
		sessionID    string
		store        *stubStore
		expectedCode codes.Code
	}{
		{
			name:         "success: session deleted",
			sessionID:    "sess-001",
			store:        &stubStore{getSessionResult: &models.Session{ID: "sess-001"}},
			expectedCode: codes.OK,
		},
		{
			name:         "session not found returns NotFound",
			sessionID:    "nonexistent",
			store:        &stubStore{getSessionErr: gorm.ErrRecordNotFound},
			expectedCode: codes.NotFound,
		},
		{
			name:      "DeleteSession error returns Internal",
			sessionID: "sess-001",
			store: &stubStore{
				getSessionResult: &models.Session{ID: "sess-001"},
				deleteSessionErr: errors.New("delete error"),
			},
			expectedCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(tt.store)
			res, err := h.Logout(context.Background(), &pb.LogoutRequest{SessionId: tt.sessionID})

			assert.Equal(t, tt.expectedCode, grpcCode(err))

			if tt.expectedCode == codes.OK {
				require.NoError(t, err)
				assert.NotNil(t, res)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthHandler_RenewAccessToken
// ---------------------------------------------------------------------------

func TestAuthHandler_RenewAccessToken(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name         string
		buildToken   func(t *testing.T) string
		store        func(t *testing.T) *stubStore
		expectedCode codes.Code
		validate     func(t *testing.T, res *pb.RenewAccessTokenResponse)
	}{
		{
			name: "success: valid token and active session",
			buildToken: func(t *testing.T) string {
				tok, _ := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T) *stubStore {
				_, claims := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return &stubStore{
					getSessionResult: &models.Session{
						ID:        claims.RegisteredClaims.ID,
						UserEmail: "alice@test.com",
						IsRevoked: false,
					},
				}
			},
			expectedCode: codes.OK,
			validate: func(t *testing.T, res *pb.RenewAccessTokenResponse) {
				assert.NotEmpty(t, res.AccessToken)
				assert.True(t, res.AccessTokenExpiresAt.AsTime().After(time.Now()))
			},
		},
		{
			name: "invalid token returns Unauthenticated",
			buildToken: func(t *testing.T) string {
				return "not.a.valid.token"
			},
			store: func(t *testing.T) *stubStore {
				return &stubStore{}
			},
			expectedCode: codes.Unauthenticated,
		},
		{
			name: "expired token returns Unauthenticated",
			buildToken: func(t *testing.T) string {
				tok, _ := mintRefreshToken(t, userID, "alice@test.com", "buyer", -time.Second)
				return tok
			},
			store: func(t *testing.T) *stubStore {
				return &stubStore{}
			},
			expectedCode: codes.Unauthenticated,
		},
		{
			name: "session not found returns NotFound",
			buildToken: func(t *testing.T) string {
				tok, _ := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T) *stubStore {
				return &stubStore{getSessionErr: gorm.ErrRecordNotFound}
			},
			expectedCode: codes.NotFound,
		},
		{
			name: "revoked session returns Unauthenticated",
			buildToken: func(t *testing.T) string {
				tok, _ := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T) *stubStore {
				_, claims := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return &stubStore{
					getSessionResult: &models.Session{
						ID:        claims.RegisteredClaims.ID,
						UserEmail: "alice@test.com",
						IsRevoked: true,
					},
				}
			},
			expectedCode: codes.Unauthenticated,
		},
		{
			name: "session email mismatch returns Unauthenticated",
			buildToken: func(t *testing.T) string {
				tok, _ := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T) *stubStore {
				_, claims := mintRefreshToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return &stubStore{
					getSessionResult: &models.Session{
						ID:        claims.RegisteredClaims.ID,
						UserEmail: "different@test.com",
						IsRevoked: false,
					},
				}
			},
			expectedCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawToken := tt.buildToken(t)
			h := newTestHandler(tt.store(t))
			res, err := h.RenewAccessToken(context.Background(), &pb.RenewAccessTokenRequest{
				RefreshToken: rawToken,
			})

			assert.Equal(t, tt.expectedCode, grpcCode(err))

			if tt.expectedCode == codes.OK {
				require.NoError(t, err)
				require.NotNil(t, res)
				if tt.validate != nil {
					tt.validate(t, res)
				}
			} else {
				require.Error(t, err)
				assert.Nil(t, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthHandler_RevokeSession
// ---------------------------------------------------------------------------

func TestAuthHandler_RevokeSession(t *testing.T) {
	tests := []struct {
		name         string
		sessionID    string
		store        *stubStore
		expectedCode codes.Code
	}{
		{
			name:         "success: session revoked",
			sessionID:    "sess-001",
			store:        &stubStore{getSessionResult: &models.Session{ID: "sess-001"}},
			expectedCode: codes.OK,
		},
		{
			name:         "session not found returns NotFound",
			sessionID:    "nonexistent",
			store:        &stubStore{getSessionErr: gorm.ErrRecordNotFound},
			expectedCode: codes.NotFound,
		},
		{
			name:      "RevokeSession store error returns Internal",
			sessionID: "sess-001",
			store: &stubStore{
				getSessionResult: &models.Session{ID: "sess-001"},
				revokeSessionErr: errors.New("revoke error"),
			},
			expectedCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(tt.store)
			res, err := h.RevokeSession(context.Background(), &pb.RevokeSessionReqeust{
				SessionId: tt.sessionID,
			})

			assert.Equal(t, tt.expectedCode, grpcCode(err))

			if tt.expectedCode == codes.OK {
				require.NoError(t, err)
				assert.NotNil(t, res)
			} else {
				require.Error(t, err)
			}
		})
	}
}
