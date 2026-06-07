package clientauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the cost factor used for new client_secret hashes. 12 is the
// 2026 baseline for confidential-client secrets (rarely-verified credentials
// can afford a higher cost than user passwords).
const bcryptCost = 12

// HashSecret hashes a plaintext client_secret with bcrypt at bcryptCost.
func HashSecret(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash client secret: %w", err)
	}
	return string(h), nil
}

// VerifySecret compares a presented plaintext against a stored bcrypt hash
// in constant time. Returns nil iff the secret matches.
func VerifySecret(hash, plaintext string) error {
	if hash == "" {
		return errors.New("clientauth: client has no stored secret")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)); err != nil {
		return ErrInvalidClient
	}
	return nil
}

// GenerateSecret returns a fresh, base64url-encoded high-entropy client
// secret suitable for storage. Use HashSecret on the returned plaintext
// before persisting; return the plaintext to the caller exactly once.
func GenerateSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
