package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "password"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Error hashing password: %s", err)
	}
	if len(hashedPassword) == 0 {
		t.Fatalf("Hashed password is empty")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "password"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Error hashing password: %s", err)
	}
	err = CheckPassword(hashedPassword, password)
	if err != nil {
		t.Fatalf("Error checking password: %s", err)
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	expiresIn := time.Hour * 24
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Error making JWT: %s", err)
	}
	if len(token) == 0 {
		t.Fatalf("JWT is empty")
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	token, err := MakeJWT(userID, tokenSecret, time.Hour*24)
	if err != nil {
		t.Fatalf("Error making JWT: %s", err)
	}
	validUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("Error validating JWT: %s", err)
	}
	if validUserID != userID {
		t.Fatalf("Invalid user ID")
	}
}
