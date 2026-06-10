package store

import (
	"sync"

	"github.com/ecomm-micro-org/auth-service/models"
	"gorm.io/gorm"
)

// MemStore is a thread-safe in-memory implementation of Storer, intended for
// use in tests. It does not persist data between process restarts.
type MemStore struct {
	mu       sync.RWMutex
	users    map[string]*models.User    // keyed by email
	sessions map[string]*models.Session // keyed by session ID
}

// NewMemStore returns an initialised, empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		users:    make(map[string]*models.User),
		sessions: make(map[string]*models.Session),
	}
}

// AddUser persists a user in memory. If a user with the same email already
// exists it is overwritten, mirroring GORM's Save behaviour.
func (m *MemStore) AddUser(u *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy so callers cannot mutate stored state via the pointer.
	cp := *u
	m.users[u.Email] = &cp
	return nil
}

// GetUserByEmail looks up a user by email and populates u with the result.
// It returns gorm.ErrRecordNotFound when no matching user exists.
func (m *MemStore) GetUserByEmail(u *models.User, email string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stored, ok := m.users[email]
	if !ok {
		return gorm.ErrRecordNotFound
	}

	*u = *stored
	return nil
}

// CreateSession persists a new session in memory.
func (m *MemStore) CreateSession(s *models.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *s
	m.sessions[s.ID] = &cp
	return nil
}

// GetSession retrieves the session whose ID matches s.ID and populates s.
// It returns gorm.ErrRecordNotFound when no matching session exists.
func (m *MemStore) GetSession(s *models.Session) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stored, ok := m.sessions[s.ID]
	if !ok {
		return gorm.ErrRecordNotFound
	}

	*s = *stored
	return nil
}

// RevokeSession marks the session with the given ID as revoked.
// It returns gorm.ErrRecordNotFound when no matching session exists.
func (m *MemStore) RevokeSession(s *models.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, ok := m.sessions[s.ID]
	if !ok {
		return gorm.ErrRecordNotFound
	}

	stored.IsRevoked = true
	return nil
}

// DeleteSession removes the session with the given ID from memory.
// It returns gorm.ErrRecordNotFound when no matching session exists.
func (m *MemStore) DeleteSession(s *models.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[s.ID]; !ok {
		return gorm.ErrRecordNotFound
	}

	delete(m.sessions, s.ID)
	return nil
}
