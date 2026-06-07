package clientauth

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	_ "crypto/sha256" // register sha256 with crypto package for thumbprints

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/hepangda/keyforge/internal/oauth/mtls"
	"github.com/hepangda/keyforge/internal/storage/clients"
)

// SelfSignedTLSClientAuthMethod implements RFC 8705 §2.2 — Self-Signed
// Certificate Mutual-TLS authentication. The client presents a certificate
// (typically self-signed) and its SHA-256 thumbprint must match the
// thumbprint of one of the public keys in the client's registered JWKS.
type SelfSignedTLSClientAuthMethod struct {
	Extractor mtls.CertExtractor
}

// NewSelfSignedTLSClientAuthMethod constructs the method.
func NewSelfSignedTLSClientAuthMethod(extractor mtls.CertExtractor) *SelfSignedTLSClientAuthMethod {
	return &SelfSignedTLSClientAuthMethod{Extractor: extractor}
}

// Name implements Method.
func (SelfSignedTLSClientAuthMethod) Name() MethodName { return MethodSelfSignedTLSAuth }

// Authenticate implements Method.
func (m *SelfSignedTLSClientAuthMethod) Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error) {
	clientID := FormClientID(r)
	if clientID == "" {
		return nil, ErrUnknownClient
	}
	cert, err := m.Extractor.Extract(r)
	if err != nil {
		if errors.Is(err, mtls.ErrNoClientCert) {
			return nil, ErrUnknownClient
		}
		return nil, fmt.Errorf("%w: extract cert: %w", ErrInvalidClient, err)
	}
	cli, lerr := lookup.GetByClientID(ctx, clientID)
	if lerr != nil {
		if errors.Is(lerr, clients.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, lerr
	}
	if cli.TokenEndpointAuthMethod != string(MethodSelfSignedTLSAuth) {
		return nil, ErrMethodMismatch
	}
	if len(cli.JWKS) == 0 {
		return nil, fmt.Errorf("%w: client missing inline jwks", ErrInvalidClient)
	}
	set, err := jwk.Parse(cli.JWKS)
	if err != nil {
		return nil, fmt.Errorf("%w: parse jwks: %w", ErrInvalidClient, err)
	}

	certThumbprint, err := jwkThumbprintForCert(cert)
	if err != nil {
		return nil, fmt.Errorf("%w: cert thumbprint: %w", ErrInvalidClient, err)
	}

	matched := false
	for it := set.Keys(ctx); it.Next(ctx); {
		pair := it.Pair()
		key, _ := pair.Value.(jwk.Key)
		tp, terr := key.Thumbprint(crypto.SHA256)
		if terr != nil {
			continue
		}
		if base64.RawURLEncoding.EncodeToString(tp) == certThumbprint {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: cert thumbprint not in client jwks", ErrInvalidClient)
	}
	return &Result{Client: cli, Method: MethodSelfSignedTLSAuth}, nil
}

// jwkThumbprintForCert computes the RFC 7638 JWK thumbprint over the
// public key inside cert.
func jwkThumbprintForCert(cert *x509.Certificate) (string, error) {
	jk, err := jwk.FromRaw(cert.PublicKey)
	if err != nil {
		return "", err
	}
	tp, err := jk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// mtls package imported so we depend on it explicitly.
var _ = mtls.Thumbprint
