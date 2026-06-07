package clientauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// generateECDSAKey is a tiny helper shared by client-auth tests.
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
