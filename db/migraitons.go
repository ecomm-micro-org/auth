package db

import (
	"log"

	"github.com/ecomm-micro-org/auth-service/models"
)

func AutoMigrate() {
	if err := Client().AutoMigrate(&models.User{}, &models.Session{}); err != nil {
		log.Fatalf("unable to migrate %v", err)
	}
}
