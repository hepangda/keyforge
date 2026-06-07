// Package pkce implements RFC 7636 verification helpers.
//
// keyforge mandates the S256 challenge method; the plaintext method is
// rejected at /oauth/authorize. This package exposes:
//
//   - Validate(challenge, verifier) — server side, given a stored
//     code_challenge and the verifier presented at /oauth/token, return nil
//     iff base64url(sha256(verifier)) == challenge.
//   - GenerateVerifier / DeriveChallenge — client-side helpers used by
//     keyforge's own SPA and by tests.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

// Errors surfaced by this package.
var (
	ErrUnsupportedMethod = errors.New("pkce: unsupported code_challenge_method")
	ErrChallengeMismatch = errors.New("pkce: challenge does not match verifier")
	ErrInvalidVerifier   = errors.New("pkce: verifier length outside 43-128 chars")
)

// MethodS256 is the only method keyforge accepts at the authorize endpoint.
const MethodS256 = "S256"

// Validate returns nil iff sha256(verifier) base64url-encoded equals
// challenge. Performs the comparison in constant time.
func Validate(method, challenge, verifier string) error {
	if !strings.EqualFold(method, MethodS256) {
		return ErrUnsupportedMethod
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return ErrInvalidVerifier
	}
	want := DeriveChallenge(verifier)
	if subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) != 1 {
		return ErrChallengeMismatch
	}
	return nil
}

// DeriveChallenge returns base64url(sha256(verifier)) without padding, per
// RFC 7636 §4.2.
func DeriveChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateVerifier returns a fresh 64-character verifier.
func GenerateVerifier() (string, error) {
	var b [48]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
