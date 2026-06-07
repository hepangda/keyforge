package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Algorithm names the JOSE alg values keyforge can mint.
type Algorithm string

// Supported JWS algorithms.
const (
	AlgRS256 Algorithm = "RS256"
	AlgES256 Algorithm = "ES256"
	AlgEdDSA Algorithm = "EdDSA"
)

// KeyPair is a generated keypair plus its JWS alg label, ready to be stored.
type KeyPair struct {
	Alg        Algorithm
	PrivatePEM []byte
	PublicPEM  []byte
}

// Generate produces a fresh keypair for the given algorithm.
func Generate(alg Algorithm) (*KeyPair, error) {
	switch alg {
	case AlgRS256:
		return generateRSA(2048)
	case AlgES256:
		return generateECDSA(elliptic.P256())
	case AlgEdDSA:
		return generateEd25519()
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func generateRSA(bits int) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generate: %w", err)
	}
	return encodePair(AlgRS256, priv, &priv.PublicKey)
}

func generateECDSA(curve elliptic.Curve) (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa generate: %w", err)
	}
	return encodePair(AlgES256, priv, &priv.PublicKey)
}

func generateEd25519() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 generate: %w", err)
	}
	return encodePair(AlgEdDSA, priv, pub)
}

func encodePair(alg Algorithm, priv, pub any) (*KeyPair, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public: %w", err)
	}
	return &KeyPair{
		Alg:        alg,
		PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		PublicPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
	}, nil
}

// ParsePrivatePEM decodes a PKCS#8 private key PEM block.
func ParsePrivatePEM(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	return key, nil
}

// ParsePublicPEM decodes a PKIX public key PEM block.
func ParsePublicPEM(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	return key, nil
}
