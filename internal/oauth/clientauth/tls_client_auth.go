package clientauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hepangda/keyforge/internal/oauth/mtls"
	"github.com/hepangda/keyforge/internal/storage/clients"
)

// TLSClientAuthMethod implements RFC 8705 §2.1 — PKI Mutual-TLS client
// authentication. The client presents a certificate validated against a
// trusted CA and the certificate's Subject DN matches the registered
// `tls_client_auth_subject_dn`.
type TLSClientAuthMethod struct {
	Extractor mtls.CertExtractor
}

// NewTLSClientAuthMethod constructs the method.
func NewTLSClientAuthMethod(extractor mtls.CertExtractor) *TLSClientAuthMethod {
	return &TLSClientAuthMethod{Extractor: extractor}
}

// Name implements Method.
func (TLSClientAuthMethod) Name() MethodName { return MethodTLSClientAuth }

// Authenticate implements Method.
func (m *TLSClientAuthMethod) Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error) {
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
	if cli.TokenEndpointAuthMethod != string(MethodTLSClientAuth) {
		return nil, ErrMethodMismatch
	}
	if cli.TLSClientAuthSubjectDN == "" {
		return nil, fmt.Errorf("%w: client missing tls_client_auth_subject_dn", ErrInvalidClient)
	}
	if !subjectDNEqual(cert.Subject.String(), cli.TLSClientAuthSubjectDN) {
		return nil, fmt.Errorf("%w: subject DN mismatch", ErrInvalidClient)
	}
	return &Result{Client: cli, Method: MethodTLSClientAuth}, nil
}

// subjectDNEqual compares two RFC 4514 DN strings allowing whitespace
// differences around commas.
func subjectDNEqual(a, b string) bool {
	return normalizeDN(a) == normalizeDN(b)
}

func normalizeDN(s string) string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.Join(parts, ",")
}
