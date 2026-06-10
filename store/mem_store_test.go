package store

import (
	"testing"
	"time"

	"github.com/ecomm-micro-org/auth-service/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// Compile-time interface check: MemStore must satisfy Storer.
var _ Storer = (*MemStore)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newUser(email, username string) *models.User {
	return &models.User{
		ID:       uuid.New(),
		Username: username,
		Email:    email,
		Password: "hashed_pw",
		Role:     models.Buyer,
		Address:  "1 Test Lane",
		Phone:    "000-0000",
	}
}

func newSession(id, email string) *models.Session {
	return &models.Session{
		ID:           id,
		UserEmail:    email,
		RefreshToken: "tok-" + id,
		IsRevoked:    false,
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
	}
}

// ---------------------------------------------------------------------------
// TestMemStore_AddUser
// ---------------------------------------------------------------------------

func TestMemStore_AddUser(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "stores new user and retrieval succeeds with matching fields",
			run: func(t *testing.T) {
				ms := NewMemStore()
				u := &models.User{
					ID:       uuid.New(),
					Username: "alice",
					Email:    "alice@example.com",
					Password: "secret",
					Role:     models.Buyer,
					Address:  "123 Main St",
					Phone:    "555-1234",
				}
				require.NoError(t, ms.AddUser(u))

				got := &models.User{}
				require.NoError(t, ms.GetUserByEmail(got, u.Email))
				assert.Equal(t, u.ID, got.ID)
				assert.Equal(t, u.Username, got.Username)
				assert.Equal(t, u.Email, got.Email)
				assert.Equal(t, u.Password, got.Password)
				assert.Equal(t, u.Role, got.Role)
				assert.Equal(t, u.Address, got.Address)
				assert.Equal(t, u.Phone, got.Phone)
			},
		},
		{
			name: "adding same email again overwrites the old entry",
			run: func(t *testing.T) {
				ms := NewMemStore()
				first := &models.User{
					ID:       uuid.New(),
					Username: "alice_v1",
					Email:    "alice@example.com",
					Password: "old_secret",
				}
				require.NoError(t, ms.AddUser(first))

				second := &models.User{
					ID:       uuid.New(),
					Username: "alice_v2",
					Email:    "alice@example.com",
					Password: "new_secret",
				}
				require.NoError(t, ms.AddUser(second))

				got := &models.User{}
				require.NoError(t, ms.GetUserByEmail(got, "alice@example.com"))
				assert.Equal(t, "alice_v2", got.Username)
				assert.Equal(t, "new_secret", got.Password)
			},
		},
		{
			name: "mutating original pointer after Add does not affect stored copy",
			run: func(t *testing.T) {
				ms := NewMemStore()
				u := &models.User{
					ID:       uuid.New(),
					Username: "bob",
					Email:    "bob@example.com",
					Password: "original_pw",
				}
				require.NoError(t, ms.AddUser(u))

				u.Username = "mutated_bob"
				u.Password = "mutated_pw"

				got := &models.User{}
				require.NoError(t, ms.GetUserByEmail(got, "bob@example.com"))
				assert.Equal(t, "bob", got.Username, "stored copy must be unaffected by mutation of original pointer")
				assert.Equal(t, "original_pw", got.Password)
			},
		},
		{
			name: "multiple distinct users stored independently",
			run: func(t *testing.T) {
				ms := NewMemStore()
				users := []*models.User{
					{ID: uuid.New(), Username: "alice", Email: "alice@example.com", Role: models.Buyer},
					{ID: uuid.New(), Username: "bob", Email: "bob@example.com", Role: models.Seller},
					{ID: uuid.New(), Username: "carol", Email: "carol@example.com", Role: models.Buyer},
				}
				for _, u := range users {
					require.NoError(t, ms.AddUser(u))
				}
				for _, u := range users {
					got := &models.User{}
					require.NoError(t, ms.GetUserByEmail(got, u.Email))
					assert.Equal(t, u.Username, got.Username)
					assert.Equal(t, u.Role, got.Role)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

// ---------------------------------------------------------------------------
// TestMemStore_GetUserByEmail
// ---------------------------------------------------------------------------

func TestMemStore_GetUserByEmail(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "returns gorm.ErrRecordNotFound on empty store",
			run: func(t *testing.T) {
				ms := NewMemStore()
				got := &models.User{}
				err := ms.GetUserByEmail(got, "nobody@example.com")
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "returns gorm.ErrRecordNotFound when email not found but other users exist",
			run: func(t *testing.T) {
				ms := NewMemStore()
				require.NoError(t, ms.AddUser(newUser("alice@example.com", "alice")))
				require.NoError(t, ms.AddUser(newUser("bob@example.com", "bob")))

				got := &models.User{}
				err := ms.GetUserByEmail(got, "nobody@example.com")
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "populates all fields of the destination struct correctly",
			run: func(t *testing.T) {
				ms := NewMemStore()
				now := time.Now().Truncate(time.Second)
				u := &models.User{
					ID:        uuid.New(),
					Username:  "alice",
					Email:     "alice@example.com",
					Password:  "hashed_pw",
					Role:      models.Seller,
					Address:   "456 Elm Ave",
					Phone:     "555-9876",
					CreatedAt: now,
					UpdatedAt: now,
				}
				require.NoError(t, ms.AddUser(u))

				got := &models.User{}
				require.NoError(t, ms.GetUserByEmail(got, u.Email))
				assert.Equal(t, u.ID, got.ID)
				assert.Equal(t, u.Username, got.Username)
				assert.Equal(t, u.Email, got.Email)
				assert.Equal(t, u.Password, got.Password)
				assert.Equal(t, u.Role, got.Role)
				assert.Equal(t, u.Address, got.Address)
				assert.Equal(t, u.Phone, got.Phone)
				assert.Equal(t, u.CreatedAt, got.CreatedAt)
				assert.Equal(t, u.UpdatedAt, got.UpdatedAt)
			},
		},
		{
			name: "mutating returned struct does not affect stored copy",
			run: func(t *testing.T) {
				ms := NewMemStore()
				u := newUser("carol@example.com", "carol")
				u.Password = "original_pw"
				require.NoError(t, ms.AddUser(u))

				got := &models.User{}
				require.NoError(t, ms.GetUserByEmail(got, u.Email))

				// Mutate the retrieved value.
				got.Username = "mutated_carol"
				got.Password = "mutated_pw"

				// Re-fetch and verify the store is unchanged.
				got2 := &models.User{}
				require.NoError(t, ms.GetUserByEmail(got2, u.Email))
				assert.Equal(t, "carol", got2.Username, "stored copy must be unaffected by mutation of returned struct")
				assert.Equal(t, "original_pw", got2.Password)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

// ---------------------------------------------------------------------------
// TestMemStore_CreateSession
// ---------------------------------------------------------------------------

func TestMemStore_CreateSession(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "new session is stored and retrievable",
			run: func(t *testing.T) {
				ms := NewMemStore()
				s := &models.Session{
					ID:           "sess-001",
					UserEmail:    "alice@example.com",
					RefreshToken: "tok-abc",
					IsRevoked:    false,
					ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
				}
				require.NoError(t, ms.CreateSession(s))

				got := &models.Session{ID: "sess-001"}
				require.NoError(t, ms.GetSession(got))
				assert.Equal(t, s.UserEmail, got.UserEmail)
				assert.Equal(t, s.RefreshToken, got.RefreshToken)
				assert.Equal(t, s.IsRevoked, got.IsRevoked)
				assert.Equal(t, s.ExpiresAt, got.ExpiresAt)
			},
		},
		{
			name: "same ID overwrites existing session",
			run: func(t *testing.T) {
				ms := NewMemStore()
				first := &models.Session{
					ID:           "sess-001",
					UserEmail:    "alice@example.com",
					RefreshToken: "tok-first",
				}
				require.NoError(t, ms.CreateSession(first))

				second := &models.Session{
					ID:           "sess-001",
					UserEmail:    "alice@example.com",
					RefreshToken: "tok-second",
				}
				require.NoError(t, ms.CreateSession(second))

				got := &models.Session{ID: "sess-001"}
				require.NoError(t, ms.GetSession(got))
				assert.Equal(t, "tok-second", got.RefreshToken)
			},
		},
		{
			name: "mutating original pointer after Create does not affect stored copy",
			run: func(t *testing.T) {
				ms := NewMemStore()
				s := &models.Session{
					ID:           "sess-002",
					UserEmail:    "bob@example.com",
					RefreshToken: "tok-original",
				}
				require.NoError(t, ms.CreateSession(s))

				s.RefreshToken = "tok-mutated"
				s.UserEmail = "mutated@example.com"

				got := &models.Session{ID: "sess-002"}
				require.NoError(t, ms.GetSession(got))
				assert.Equal(t, "tok-original", got.RefreshToken, "stored copy must be unaffected by mutation of original pointer")
				assert.Equal(t, "bob@example.com", got.UserEmail)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

// ---------------------------------------------------------------------------
// TestMemStore_GetSession
// ---------------------------------------------------------------------------

func TestMemStore_GetSession(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "returns gorm.ErrRecordNotFound on empty store",
			run: func(t *testing.T) {
				ms := NewMemStore()
				got := &models.Session{ID: "missing"}
				err := ms.GetSession(got)
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "returns gorm.ErrRecordNotFound when ID does not match",
			run: func(t *testing.T) {
				ms := NewMemStore()
				require.NoError(t, ms.CreateSession(newSession("sess-001", "alice@example.com")))

				got := &models.Session{ID: "sess-999"}
				err := ms.GetSession(got)
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "populates all fields correctly including ExpiresAt",
			run: func(t *testing.T) {
				ms := NewMemStore()
				expiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
				s := &models.Session{
					ID:           "sess-001",
					UserEmail:    "alice@example.com",
					RefreshToken: "tok-xyz",
					IsRevoked:    false,
					ExpiresAt:    expiry,
				}
				require.NoError(t, ms.CreateSession(s))

				got := &models.Session{ID: "sess-001"}
				require.NoError(t, ms.GetSession(got))
				assert.Equal(t, s.ID, got.ID)
				assert.Equal(t, s.UserEmail, got.UserEmail)
				assert.Equal(t, s.RefreshToken, got.RefreshToken)
				assert.Equal(t, s.IsRevoked, got.IsRevoked)
				assert.Equal(t, s.ExpiresAt, got.ExpiresAt)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

// ---------------------------------------------------------------------------
// TestMemStore_RevokeSession
// ---------------------------------------------------------------------------

func TestMemStore_RevokeSession(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "sets IsRevoked=true on existing session",
			run: func(t *testing.T) {
				ms := NewMemStore()
				s := newSession("sess-001", "alice@example.com")
				s.IsRevoked = false
				require.NoError(t, ms.CreateSession(s))

				require.NoError(t, ms.RevokeSession(&models.Session{ID: "sess-001"}))

				got := &models.Session{ID: "sess-001"}
				require.NoError(t, ms.GetSession(got))
				assert.True(t, got.IsRevoked)
			},
		},
		{
			name: "returns gorm.ErrRecordNotFound for non-existent session",
			run: func(t *testing.T) {
				ms := NewMemStore()
				err := ms.RevokeSession(&models.Session{ID: "nonexistent"})
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "revoking one session does not affect others",
			run: func(t *testing.T) {
				ms := NewMemStore()
				ids := []string{"sess-001", "sess-002", "sess-003"}
				for _, id := range ids {
					s := newSession(id, "alice@example.com")
					s.IsRevoked = false
					require.NoError(t, ms.CreateSession(s))
				}

				require.NoError(t, ms.RevokeSession(&models.Session{ID: "sess-002"}))

				for _, id := range []string{"sess-001", "sess-003"} {
					got := &models.Session{ID: id}
					require.NoError(t, ms.GetSession(got))
					assert.False(t, got.IsRevoked, "session %s should not be revoked", id)
				}

				revoked := &models.Session{ID: "sess-002"}
				require.NoError(t, ms.GetSession(revoked))
				assert.True(t, revoked.IsRevoked)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

// ---------------------------------------------------------------------------
// TestMemStore_DeleteSession
// ---------------------------------------------------------------------------

func TestMemStore_DeleteSession(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "deletes session and subsequent GetSession returns gorm.ErrRecordNotFound",
			run: func(t *testing.T) {
				ms := NewMemStore()
				require.NoError(t, ms.CreateSession(newSession("sess-001", "alice@example.com")))
				require.NoError(t, ms.DeleteSession(&models.Session{ID: "sess-001"}))

				got := &models.Session{ID: "sess-001"}
				err := ms.GetSession(got)
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "returns gorm.ErrRecordNotFound for non-existent session",
			run: func(t *testing.T) {
				ms := NewMemStore()
				err := ms.DeleteSession(&models.Session{ID: "nonexistent"})
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "deleting one session does not affect others",
			run: func(t *testing.T) {
				ms := NewMemStore()
				ids := []string{"sess-001", "sess-002", "sess-003"}
				for _, id := range ids {
					require.NoError(t, ms.CreateSession(newSession(id, "alice@example.com")))
				}

				require.NoError(t, ms.DeleteSession(&models.Session{ID: "sess-002"}))

				for _, id := range []string{"sess-001", "sess-003"} {
					got := &models.Session{ID: id}
					require.NoError(t, ms.GetSession(got), "session %s should still exist", id)
					assert.Equal(t, id, got.ID)
				}

				got := &models.Session{ID: "sess-002"}
				err := ms.GetSession(got)
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
		{
			name: "double-delete returns gorm.ErrRecordNotFound",
			run: func(t *testing.T) {
				ms := NewMemStore()
				require.NoError(t, ms.CreateSession(newSession("sess-001", "alice@example.com")))
				require.NoError(t, ms.DeleteSession(&models.Session{ID: "sess-001"}))

				err := ms.DeleteSession(&models.Session{ID: "sess-001"})
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}
