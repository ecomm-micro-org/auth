package token

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserClaims(t *testing.T) {
	tests := []struct {
		name        string
		id          uuid.UUID
		email       string
		role        string
		duration    time.Duration
		expectError bool
		validate    func(t *testing.T, claims *UserClaims)
	}{
		{
			name:        "creates valid claims with all fields populated",
			id:          uuid.New(),
			email:       "user@example.com",
			role:        "customer",
			duration:    15 * time.Minute,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.NotEmpty(t, claims.ID, "user ID must not be empty")
				assert.Equal(t, "user@example.com", claims.Email)
				assert.Equal(t, "customer", claims.Role)
				assert.NotEmpty(t, claims.RegisteredClaims.ID, "JWT ID must not be empty")
				assert.Equal(t, "user@example.com", claims.RegisteredClaims.Subject)
				assert.WithinDuration(t, time.Now(), claims.IssuedAt.Time, 2*time.Second)
				assert.WithinDuration(t, time.Now().Add(15*time.Minute), claims.ExpiresAt.Time, 2*time.Second)
			},
		},
		{
			name:        "each call generates a unique JWT ID",
			id:          uuid.New(),
			email:       "user@example.com",
			role:        "admin",
			duration:    time.Hour,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				other, err := NewUserClaims(uuid.New(), "other@example.com", "admin", time.Hour)
				require.NoError(t, err)
				assert.NotEqual(t, claims.RegisteredClaims.ID, other.RegisteredClaims.ID,
					"two calls should produce distinct JWT IDs")
			},
		},
		{
			name:        "expiry is set relative to duration — short duration",
			id:          uuid.New(),
			email:       "short@example.com",
			role:        "customer",
			duration:    1 * time.Second,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.WithinDuration(t, time.Now().Add(time.Second), claims.ExpiresAt.Time, 2*time.Second)
			},
		},
		{
			name:        "expiry is set relative to duration — long duration",
			id:          uuid.New(),
			email:       "long@example.com",
			role:        "admin",
			duration:    24 * time.Hour,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.WithinDuration(t, time.Now().Add(24*time.Hour), claims.ExpiresAt.Time, 2*time.Second)
			},
		},
		{
			name:        "zero UUID is accepted as user ID",
			id:          uuid.UUID{},
			email:       "zero@example.com",
			role:        "customer",
			duration:    time.Minute,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.Equal(t, uuid.UUID{}, claims.ID)
			},
		},
		{
			name:        "admin role is preserved in claims",
			id:          uuid.New(),
			email:       "admin@example.com",
			role:        "admin",
			duration:    time.Hour,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.Equal(t, "admin", claims.Role)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := NewUserClaims(tt.id, tt.email, tt.role, tt.duration)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, claims)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, claims)
			tt.validate(t, claims)
		})
	}
}

func TestCreateToken(t *testing.T) {
	const validSecret = "12345678901234567890123456789012"

	tests := []struct {
		name        string
		secretKey   string
		id          uuid.UUID
		email       string
		role        string
		duration    time.Duration
		expectError bool
		validate    func(t *testing.T, tokenStr string, claims *UserClaims)
	}{
		{
			name:        "creates a valid signed token",
			secretKey:   validSecret,
			id:          uuid.New(),
			email:       "user@example.com",
			role:        "customer",
			duration:    15 * time.Minute,
			expectError: false,
			validate: func(t *testing.T, tokenStr string, claims *UserClaims) {
				assert.NotEmpty(t, tokenStr, "token string must not be empty")
				assert.NotNil(t, claims)
			},
		},
		{
			name:        "returned claims match the input values",
			secretKey:   validSecret,
			id:          uuid.New(),
			email:       "match@example.com",
			role:        "admin",
			duration:    time.Hour,
			expectError: false,
			validate: func(t *testing.T, tokenStr string, claims *UserClaims) {
				assert.Equal(t, "match@example.com", claims.Email)
				assert.Equal(t, "admin", claims.Role)
				assert.WithinDuration(t, time.Now().Add(time.Hour), claims.ExpiresAt.Time, 2*time.Second)
			},
		},
		{
			name:        "two calls produce different token strings",
			secretKey:   validSecret,
			id:          uuid.New(),
			email:       "dup@example.com",
			role:        "customer",
			duration:    time.Hour,
			expectError: false,
			validate: func(t *testing.T, tokenStr string, claims *UserClaims) {
				maker := NewJWTMaker(validSecret)
				other, _, err := maker.CreateToken(uuid.New(), "other@example.com", "customer", time.Hour)
				require.NoError(t, err)
				assert.NotEqual(t, tokenStr, other, "distinct calls should produce distinct tokens")
			},
		},
		{
			name:        "token is a well-formed JWT (three dot-separated parts)",
			secretKey:   validSecret,
			id:          uuid.New(),
			email:       "jwt@example.com",
			role:        "customer",
			duration:    time.Minute,
			expectError: false,
			validate: func(t *testing.T, tokenStr string, claims *UserClaims) {
				// a JWT has exactly three base64url segments separated by dots
				parts := 0
				for _, c := range tokenStr {
					if c == '.' {
						parts++
					}
				}
				assert.Equal(t, 2, parts, "JWT must contain exactly two dots (header.payload.signature)")
			},
		},
		{
			name:        "short-lived token has expiry close to now",
			secretKey:   validSecret,
			id:          uuid.New(),
			email:       "short@example.com",
			role:        "customer",
			duration:    1 * time.Second,
			expectError: false,
			validate: func(t *testing.T, tokenStr string, claims *UserClaims) {
				assert.WithinDuration(t, time.Now().Add(time.Second), claims.ExpiresAt.Time, 2*time.Second)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maker := NewJWTMaker(tt.secretKey)
			tokenStr, claims, err := maker.CreateToken(tt.id, tt.email, tt.role, tt.duration)

			if tt.expectError {
				require.Error(t, err)
				assert.Empty(t, tokenStr)
				assert.Nil(t, claims)
				return
			}

			require.NoError(t, err)
			tt.validate(t, tokenStr, claims)
		})
	}
}

func TestVerifyToken(t *testing.T) {
	const validSecret = "12345678901234567890123456789012"
	const otherSecret = "99999999999999999999999999999999"

	// helper: mint a fresh token with the given maker and duration
	mintToken := func(t *testing.T, maker *JWTMaker, duration time.Duration) (string, *UserClaims) {
		t.Helper()
		tokenStr, claims, err := maker.CreateToken(uuid.New(), "user@example.com", "customer", duration)
		require.NoError(t, err, "minting token must not fail")
		return tokenStr, claims
	}

	tests := []struct {
		name        string
		buildToken  func(t *testing.T) string
		verifyWith  string // secret used by the verifying maker
		expectError bool
		validate    func(t *testing.T, claims *UserClaims)
	}{
		{
			name: "verifies a valid token and returns correct claims",
			buildToken: func(t *testing.T) string {
				tok, _ := mintToken(t, NewJWTMaker(validSecret), 15*time.Minute)
				return tok
			},
			verifyWith:  validSecret,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.Equal(t, "user@example.com", claims.Email)
				assert.Equal(t, "customer", claims.Role)
				assert.NotEmpty(t, claims.RegisteredClaims.ID)
				assert.True(t, claims.ExpiresAt.Time.After(time.Now()),
					"expiry must be in the future for a fresh token")
			},
		},
		{
			name: "returns error for a completely invalid token string",
			buildToken: func(t *testing.T) string {
				return "this.is.not.a.jwt"
			},
			verifyWith:  validSecret,
			expectError: true,
		},
		{
			name: "returns error for an empty token string",
			buildToken: func(t *testing.T) string {
				return ""
			},
			verifyWith:  validSecret,
			expectError: true,
		},
		{
			name: "returns error when token is signed with a different secret",
			buildToken: func(t *testing.T) string {
				tok, _ := mintToken(t, NewJWTMaker(otherSecret), 15*time.Minute)
				return tok
			},
			verifyWith:  validSecret,
			expectError: true,
		},
		{
			name: "returns error for an expired token",
			buildToken: func(t *testing.T) string {
				// mint with a negative duration so it expires immediately
				tok, _ := mintToken(t, NewJWTMaker(validSecret), -1*time.Second)
				return tok
			},
			verifyWith:  validSecret,
			expectError: true,
		},
		{
			name: "returns error for a token with only two parts (malformed)",
			buildToken: func(t *testing.T) string {
				return "header.payload"
			},
			verifyWith:  validSecret,
			expectError: true,
		},
		{
			name: "round-trip: token created then immediately verified preserves all claims",
			buildToken: func(t *testing.T) string {
				tok, _ := mintToken(t, NewJWTMaker(validSecret), time.Hour)
				return tok
			},
			verifyWith:  validSecret,
			expectError: false,
			validate: func(t *testing.T, claims *UserClaims) {
				assert.Equal(t, "user@example.com", claims.Email)
				assert.Equal(t, "customer", claims.Role)
				assert.NotEmpty(t, claims.ID)
				assert.NotEmpty(t, claims.RegisteredClaims.ID)
				assert.WithinDuration(t, time.Now().Add(time.Hour), claims.ExpiresAt.Time, 2*time.Second)
			},
		},
		{
			name: "returns error for a random base64 string that looks like a JWT",
			buildToken: func(t *testing.T) string {
				return "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"
			},
			verifyWith:  validSecret,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr := tt.buildToken(t)
			maker := NewJWTMaker(tt.verifyWith)
			claims, err := maker.VerifyToken(tokenStr)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, claims)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, claims)
			if tt.validate != nil {
				tt.validate(t, claims)
			}
		})
	}
}
