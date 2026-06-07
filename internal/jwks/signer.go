package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Signer signs arbitrary payloads with keyforge's active signing key. It is
// the cross-cutting abstraction used by ID tokens, JAR, JARM, and DPoP
// server-issued nonces. Tests can substitute a fake implementation.
type Signer interface {
	// Sign produces a compact JWS over rawPayload with the current active
	// signing key for the given tenant scope. The header's `alg` and `kid`
	// are filled in automatically.
	Sign(ctx context.Context, tenantID uuid.UUID, rawPayload []byte) (string, error)

	// SignClaims marshals the claims to JSON and delegates to Sign. Use
	// this for typed payloads (e.g. JWT, JARM responses).
	SignClaims(ctx context.Context, tenantID uuid.UUID, claims any) (string, error)

	// SignJWT signs a jwt.Token. The same active key is used as in Sign.
	SignJWT(ctx context.Context, tenantID uuid.UUID, token jwt.Token) (string, error)
}

// StoreSigner adapts a Store to the Signer interface.
type StoreSigner struct {
	store Store
}

// NewSigner wraps a Store with a Signer.
func NewSigner(s Store) *StoreSigner { return &StoreSigner{store: s} }

// Sign implements Signer.
func (s *StoreSigner) Sign(ctx context.Context, tenantID uuid.UUID, rawPayload []byte) (string, error) {
	key, err := s.store.Active(ctx, tenantID, UseSig)
	if err != nil {
		return "", err
	}
	return signRaw(key, rawPayload)
}

// SignClaims implements Signer.
func (s *StoreSigner) SignClaims(ctx context.Context, tenantID uuid.UUID, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	return s.Sign(ctx, tenantID, payload)
}

// SignJWT implements Signer.
func (s *StoreSigner) SignJWT(ctx context.Context, tenantID uuid.UUID, token jwt.Token) (string, error) {
	key, err := s.store.Active(ctx, tenantID, UseSig)
	if err != nil {
		return "", err
	}
	alg, err := AlgToJWA(key.Alg)
	if err != nil {
		return "", err
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, key.KID); err != nil {
		return "", err
	}
	if err := hdr.Set(jws.AlgorithmKey, alg.String()); err != nil {
		return "", err
	}
	signed, err := jwt.Sign(
		token,
		jwt.WithKey(alg, key.PrivateKey, jws.WithProtectedHeaders(hdr)),
	)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(signed), nil
}

func signRaw(key *Key, payload []byte) (string, error) {
	alg, err := AlgToJWA(key.Alg)
	if err != nil {
		return "", err
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, key.KID); err != nil {
		return "", err
	}
	signed, err := jws.Sign(
		payload,
		jws.WithKey(alg, key.PrivateKey, jws.WithProtectedHeaders(hdr)),
	)
	if err != nil {
		return "", fmt.Errorf("jws sign: %w", err)
	}
	return string(signed), nil
}

// Compile-time assertion.
var _ Signer = (*StoreSigner)(nil)
