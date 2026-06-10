package models

import (
	"time"
)

type Session struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	UserEmail    string    `json:"user_email" gorm:"column:user_email"`
	RefreshToken string    `json:"refresh_token" gorm:"column:refresh_token"`
	IsRevoked    bool      `json:"is_revoked" gorm:"column:is_revoked"`
	ExpiresAt    time.Time `json:"expires_at" gorm:"column:expires_at"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    time.Time
}

func NewSession() *Session {
	return &Session{}
}
