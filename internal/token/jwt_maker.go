package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTMaker struct {
	secretKey string
	issuer    string
}

func NewJWTMaker(secretkey, issuer string) *JWTMaker {
	return &JWTMaker{
		secretKey: secretkey,
		issuer:    issuer,
	}
}

func (maker *JWTMaker) CreateToken(id uuid.UUID, email string, role string, duration time.Duration) (string, *UserClaims, error) {
	claims, err := NewUserClaims(id, email, role, maker.issuer, duration)
	if err != nil {
		return "", nil, fmt.Errorf("unable to create claims")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", nil, fmt.Errorf("error signing token : %v", err)
	}

	return tokenStr, claims, nil
}

func (maker *JWTMaker) VerifyToken(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("invalid signing method used")
		}
		return []byte(maker.secretKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token : %v", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}
