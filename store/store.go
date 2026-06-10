package store

import "github.com/ecomm-micro-org/auth-service/models"

type Storer interface {
	AddUser(u *models.User) error
	GetUserByEmail(u *models.User, email string) error
	CreateSession(s *models.Session) error
	GetSession(s *models.Session) error
	RevokeSession(s *models.Session) error
	DeleteSession(s *models.Session) error
}
