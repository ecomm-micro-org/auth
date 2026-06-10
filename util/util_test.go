package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "returns hashed password for normal input",
			password: "hello_john_doe",
		},
		{
			name:     "returns hashed password for short input",
			password: "abc",
		},
		{
			name:     "returns hashed password for empty string",
			password: "",
		},
		{
			name:     "returns hashed password for input with special characters",
			password: "p@$$w0rd!#&*()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := HashPassword(tt.password)
			require.NoError(t, err, "should not be any hashing errors")
			assert.NotEmpty(t, actual, "hash should not be empty")
		})
	}

	// bcrypt salts are random — two hashes of the same input must differ.
	t.Run("same password produces different hashes on each call", func(t *testing.T) {
		h1, err := HashPassword("same_input")
		require.NoError(t, err)
		h2, err := HashPassword("same_input")
		require.NoError(t, err)
		assert.NotEqual(t, h1, h2, "bcrypt must produce a unique hash per call due to random salt")
	})
}

func TestCheckPassword(t *testing.T) {
	tests := []struct {
		name           string
		password       string
		hashedPassword func(t *testing.T, password string) string
		validate       func(t *testing.T, p, h string)
	}{
		{
			name:     "mismatched password returns error",
			password: "hello_john_doe",
			hashedPassword: func(t *testing.T, _ string) string {
				// Hash of a completely different password.
				return "$2a$10$CLcTsbLw0Zjk2Ja.1UYC0OGwMfU4nha47tdJ3hnLq4dMhu7wT7GFw"
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.Error(t, err, "error must be non-nil when password and hash do not match")
			},
		},
		{
			name:     "matching password returns no error",
			password: "hello_john_doe",
			hashedPassword: func(t *testing.T, p string) string {
				hash, err := HashPassword(p)
				require.NoError(t, err, "must return no error")
				return hash
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.NoError(t, err, "error must be nil when password and hash are equal")
			},
		},
		{
			name:     "empty password against non-empty hash returns error",
			password: "",
			hashedPassword: func(t *testing.T, _ string) string {
				hash, err := HashPassword("non_empty_password")
				require.NoError(t, err)
				return hash
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.Error(t, err, "empty password must not match a hash of a non-empty password")
			},
		},
		{
			name:     "empty password matches hash of empty password",
			password: "",
			hashedPassword: func(t *testing.T, p string) string {
				hash, err := HashPassword(p)
				require.NoError(t, err)
				return hash
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.NoError(t, err, "empty password must match the hash of an empty password")
			},
		},
		{
			name:     "password with different casing returns error",
			password: "Hello_John_Doe",
			hashedPassword: func(t *testing.T, _ string) string {
				hash, err := HashPassword("hello_john_doe")
				require.NoError(t, err)
				return hash
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.Error(t, err, "bcrypt comparison must be case-sensitive")
			},
		},
		{
			name:     "completely different password returns error",
			password: "totally_different_password",
			hashedPassword: func(t *testing.T, _ string) string {
				hash, err := HashPassword("hello_john_doe")
				require.NoError(t, err)
				return hash
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.Error(t, err, "a completely different password must not match")
			},
		},
		{
			name:     "malformed hash string returns error",
			password: "hello_john_doe",
			hashedPassword: func(t *testing.T, _ string) string {
				return "not_a_valid_bcrypt_hash"
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.Error(t, err, "an invalid hash format must return an error")
			},
		},
		{
			name:     "password with leading and trailing spaces does not match trimmed hash",
			password: "  hello_john_doe  ",
			hashedPassword: func(t *testing.T, _ string) string {
				hash, err := HashPassword("hello_john_doe")
				require.NoError(t, err)
				return hash
			},
			validate: func(t *testing.T, p, h string) {
				err := CheckPassword(p, h)
				assert.Error(t, err, "password with extra whitespace must not match hash of trimmed version")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.hashedPassword(t, tt.password)
			tt.validate(t, tt.password, h)
		})
	}
}
