package services_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ecomm-micro-org/auth-service/internal/token"
	"github.com/ecomm-micro-org/auth-service/models"
	"github.com/ecomm-micro-org/auth-service/pb"
	"github.com/ecomm-micro-org/auth-service/services"
	"github.com/ecomm-micro-org/auth-service/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	testSecret = "test-secret-key-that-is-long-enough"
	testIssuer = "test-issuer"
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

func (s *stubStore) AddUser(u *models.User) error { return s.addUserErr }

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

func (s *stubStore) GetSession(s2 *models.Session) error {
	if s.getSessionErr != nil {
		return s.getSessionErr
	}
	if s.getSessionResult != nil {
		*s2 = *s.getSessionResult
	}
	return nil
}

func (s *stubStore) RevokeSession(_ *models.Session) error { return s.revokeSessionErr }
func (s *stubStore) DeleteSession(_ *models.Session) error { return s.deleteSessionErr }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestService(st *stubStore) *services.AuthService {
	return services.NewAuthService(st, token.NewJWTMaker(testSecret, testIssuer))
}

func mustHashPassword(t *testing.T, pw string) string {
	t.Helper()
	h, err := util.HashPassword(pw)
	require.NoError(t, err)
	return h
}

func mustMintToken(t *testing.T, id uuid.UUID, email, role string, dur time.Duration) (string, *token.UserClaims) {
	t.Helper()
	maker := token.NewJWTMaker(testSecret, testIssuer)
	tok, claims, err := maker.CreateToken(id, email, role, dur)
	require.NoError(t, err)
	return tok, claims
}

// ---------------------------------------------------------------------------
// TestAuthService_Signin
// ---------------------------------------------------------------------------

func TestAuthService_Signin(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		email       string
		password    string
		role        string
		phone       string
		address     string
		store       *stubStore
		expectError bool
		validate    func(t *testing.T, res *pb.SigninResponse)
	}{
		{
			name:     "success: response contains tokens and user fields",
			username: "alice",
			email:    "alice@test.com",
			password: "password123",
			role:     "buyer",
			phone:    "5551234",
			address:  "1 Main St",
			store:    &stubStore{},
			validate: func(t *testing.T, res *pb.SigninResponse) {
				assert.NotEmpty(t, res.AccessToken)
				assert.NotEmpty(t, res.RefreshToken)
				assert.NotEmpty(t, res.SessionId)
				require.NotNil(t, res.User)
				assert.Equal(t, "alice@test.com", res.User.Email)
				assert.Equal(t, "alice", res.User.Username)
				assert.Equal(t, "buyer", res.User.Role)
				assert.Equal(t, "5551234", res.User.Phone)
				assert.Equal(t, "1 Main St", res.User.Address)
				assert.NotNil(t, res.AccessTokenExpiresAt)
				assert.NotNil(t, res.RefreshTokenExpiresAt)
			},
		},
		{
			name:        "AddUser error is propagated",
			username:    "bob",
			email:       "bob@test.com",
			password:    "password123",
			role:        "buyer",
			phone:       "5551234",
			address:     "1 Main St",
			store:       &stubStore{addUserErr: errors.New("db error")},
			expectError: true,
		},
		{
			name:        "CreateSession error is propagated",
			username:    "carol",
			email:       "carol@test.com",
			password:    "password123",
			role:        "buyer",
			phone:       "5551234",
			address:     "1 Main St",
			store:       &stubStore{createSessionErr: errors.New("session db error")},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.store)
			res, err := svc.Signin(tt.username, tt.email, tt.password, tt.role, tt.phone, tt.address)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, res)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, res)
			if tt.validate != nil {
				tt.validate(t, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthService_Login
// ---------------------------------------------------------------------------

func TestAuthService_Login(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		password    string
		store       func(t *testing.T) *stubStore
		expectError bool
		expectErr   error // if set, error must wrap this value
		validate    func(t *testing.T, res *pb.LoginResponse)
	}{
		{
			name:     "success: correct credentials return tokens and user",
			email:    "alice@test.com",
			password: "password123",
			store: func(t *testing.T) *stubStore {
				return &stubStore{
					getUserResult: &models.User{
						ID:       uuid.New(),
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
				require.NotNil(t, res.User)
				assert.Equal(t, "alice@test.com", res.User.Email)
			},
		},
		{
			name:     "user not found returns gorm.ErrRecordNotFound",
			email:    "nobody@test.com",
			password: "password123",
			store: func(t *testing.T) *stubStore {
				return &stubStore{getUserErr: gorm.ErrRecordNotFound}
			},
			expectError: true,
			expectErr:   gorm.ErrRecordNotFound,
		},
		{
			name:     "wrong password returns bcrypt.ErrMismatchedHashAndPassword",
			email:    "alice@test.com",
			password: "wrongpassword",
			store: func(t *testing.T) *stubStore {
				return &stubStore{
					getUserResult: &models.User{
						ID:       uuid.New(),
						Email:    "alice@test.com",
						Password: mustHashPassword(t, "password123"),
						Role:     models.Buyer,
					},
				}
			},
			expectError: true,
			expectErr:   bcrypt.ErrMismatchedHashAndPassword,
		},
		{
			name:     "GetUserByEmail store error is propagated",
			email:    "alice@test.com",
			password: "password123",
			store: func(t *testing.T) *stubStore {
				return &stubStore{getUserErr: errors.New("db error")}
			},
			expectError: true,
		},
		{
			name:     "CreateSession error is propagated",
			email:    "alice@test.com",
			password: "password123",
			store: func(t *testing.T) *stubStore {
				return &stubStore{
					getUserResult: &models.User{
						ID:       uuid.New(),
						Email:    "alice@test.com",
						Password: mustHashPassword(t, "password123"),
						Role:     models.Buyer,
					},
					createSessionErr: errors.New("session db error"),
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.store(t))
			res, err := svc.Login(tt.email, tt.password)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectErr != nil {
					assert.ErrorIs(t, err, tt.expectErr)
				}
				assert.Nil(t, res)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, res)
			if tt.validate != nil {
				tt.validate(t, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthService_Logout
// ---------------------------------------------------------------------------

func TestAuthService_Logout(t *testing.T) {
	tests := []struct {
		name        string
		sessionID   string
		store       *stubStore
		expectError bool
		expectErr   error
	}{
		{
			name:      "success: session found and deleted",
			sessionID: "sess-001",
			store: &stubStore{
				getSessionResult: &models.Session{
					ID:        "sess-001",
					UserEmail: "alice@test.com",
					IsRevoked: false,
				},
			},
		},
		{
			name:        "session not found returns gorm.ErrRecordNotFound",
			sessionID:   "nonexistent",
			store:       &stubStore{getSessionErr: gorm.ErrRecordNotFound},
			expectError: true,
			expectErr:   gorm.ErrRecordNotFound,
		},
		{
			name:      "DeleteSession error is propagated",
			sessionID: "sess-001",
			store: &stubStore{
				getSessionResult: &models.Session{ID: "sess-001"},
				deleteSessionErr: errors.New("delete error"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.store)
			err := svc.Logout(tt.sessionID)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectErr != nil {
					assert.ErrorIs(t, err, tt.expectErr)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthService_RenewAccessToken
// ---------------------------------------------------------------------------

func TestAuthService_RenewAccessToken(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name        string
		buildToken  func(t *testing.T) string
		store       func(t *testing.T, rawToken string) *stubStore
		expectError bool
		validate    func(t *testing.T, res *pb.RenewAccessTokenResponse)
	}{
		{
			name: "success: valid token and active session returns new access token",
			buildToken: func(t *testing.T) string {
				tok, _ := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T, rawToken string) *stubStore {
				_, claims := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return &stubStore{
					getSessionResult: &models.Session{
						ID:        claims.RegisteredClaims.ID,
						UserEmail: "alice@test.com",
						IsRevoked: false,
					},
				}
			},
			validate: func(t *testing.T, res *pb.RenewAccessTokenResponse) {
				assert.NotEmpty(t, res.AccessToken)
				assert.NotNil(t, res.AccessTokenExpiresAt)
				assert.True(t, res.AccessTokenExpiresAt.AsTime().After(time.Now()))
			},
		},
		{
			name: "invalid token string returns error",
			buildToken: func(t *testing.T) string {
				return "not.a.valid.token"
			},
			store: func(t *testing.T, _ string) *stubStore {
				return &stubStore{}
			},
			expectError: true,
		},
		{
			name: "session not found returns gorm.ErrRecordNotFound",
			buildToken: func(t *testing.T) string {
				tok, _ := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T, _ string) *stubStore {
				return &stubStore{getSessionErr: gorm.ErrRecordNotFound}
			},
			expectError: true,
		},
		{
			name: "revoked session returns error",
			buildToken: func(t *testing.T) string {
				tok, _ := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T, _ string) *stubStore {
				_, claims := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return &stubStore{
					getSessionResult: &models.Session{
						ID:        claims.RegisteredClaims.ID,
						UserEmail: "alice@test.com",
						IsRevoked: true,
					},
				}
			},
			expectError: true,
		},
		{
			name: "session email mismatch returns error",
			buildToken: func(t *testing.T) string {
				tok, _ := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return tok
			},
			store: func(t *testing.T, _ string) *stubStore {
				_, claims := mustMintToken(t, userID, "alice@test.com", "buyer", time.Hour)
				return &stubStore{
					getSessionResult: &models.Session{
						ID:        claims.RegisteredClaims.ID,
						UserEmail: "different@test.com",
						IsRevoked: false,
					},
				}
			},
			expectError: true,
		},
		{
			name: "expired refresh token returns error",
			buildToken: func(t *testing.T) string {
				tok, _ := mustMintToken(t, userID, "alice@test.com", "buyer", -time.Second)
				return tok
			},
			store: func(t *testing.T, _ string) *stubStore {
				return &stubStore{}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawToken := tt.buildToken(t)
			svc := newTestService(tt.store(t, rawToken))
			res, err := svc.RenewAccessToken(rawToken)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, res)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, res)
			if tt.validate != nil {
				tt.validate(t, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAuthService_RevokeSession
// ---------------------------------------------------------------------------

func TestAuthService_RevokeSession(t *testing.T) {
	tests := []struct {
		name        string
		sessionID   string
		store       *stubStore
		expectError bool
		expectErr   error
	}{
		{
			name:      "success: existing session is revoked",
			sessionID: "sess-001",
			store: &stubStore{
				getSessionResult: &models.Session{
					ID:        "sess-001",
					UserEmail: "alice@test.com",
					IsRevoked: false,
				},
			},
		},
		{
			name:        "session not found returns gorm.ErrRecordNotFound",
			sessionID:   "nonexistent",
			store:       &stubStore{getSessionErr: gorm.ErrRecordNotFound},
			expectError: true,
			expectErr:   gorm.ErrRecordNotFound,
		},
		{
			name:      "RevokeSession store error is propagated",
			sessionID: "sess-001",
			store: &stubStore{
				getSessionResult: &models.Session{ID: "sess-001"},
				revokeSessionErr: errors.New("revoke db error"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.store)
			err := svc.RevokeSession(tt.sessionID)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectErr != nil {
					assert.ErrorIs(t, err, tt.expectErr)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}
