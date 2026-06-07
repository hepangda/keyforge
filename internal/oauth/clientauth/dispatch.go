// Package clientauth implements every OAuth 2.0 / OIDC client-authentication
// method keyforge supports at the token, introspection, and revocation
// endpoints. The registered methods are dispatched through Authenticator
// based on the request shape and the client's `token_endpoint_auth_method`.
//
// Implementations live in sibling files under this package:
//
//   - none.go                       — public clients
//   - secret_basic.go               — RFC 6749 §2.3.1 HTTP Basic
//   - secret_post.go                — client_id/client_secret in form body
//   - private_key_jwt.go            — RFC 7523 §2.2 client assertion JWT
//   - tls_client_auth.go            — RFC 8705 §2.1 (PKI mTLS)
//   - self_signed_tls_client_auth.go — RFC 8705 §2.2 (self-signed mTLS)
package clientauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hepangda/keyforge/internal/storage/clients"
)

// MethodName labels each client-authentication method per the IANA
// "OAuth Token Endpoint Authentication Methods" registry.
type MethodName string

// Supported method names.
const (
	MethodNone              MethodName = "none"
	MethodSecretBasic       MethodName = "client_secret_basic"
	MethodSecretPost        MethodName = "client_secret_post"
	MethodPrivateKeyJWT     MethodName = "private_key_jwt"
	MethodTLSClientAuth     MethodName = "tls_client_auth"
	MethodSelfSignedTLSAuth MethodName = "self_signed_tls_client_auth"
)

// Errors surfaced by client-authentication code. Handlers translate these
// into OAuth 2.0 error responses.
var (
	ErrInvalidClient     = errors.New("clientauth: invalid client credentials")
	ErrUnknownClient     = errors.New("clientauth: unknown client_id")
	ErrMissingClientID   = errors.New("clientauth: missing client_id")
	ErrMethodMismatch    = errors.New("clientauth: registered method does not match presented credentials")
	ErrUnsupportedMethod = errors.New("clientauth: unsupported client auth method")
)

// ClientLookup loads a client by its public client_id from the active tenant.
// Tests substitute a fake; production passes a clients.Repository instance.
type ClientLookup interface {
	GetByClientID(ctx context.Context, clientID string) (*clients.Client, error)
}

// Result is what Method.Authenticate returns on success.
type Result struct {
	Client *clients.Client
	Method MethodName
}

// Method authenticates a request using one specific mechanism.
//
// Each implementation returns:
//   - ErrUnknownClient when its detection criteria don't match (so dispatch
//     can fall through to the next method);
//   - ErrInvalidClient when the criteria match but the credential is wrong;
//   - ErrMethodMismatch when the client_id is found but is registered with
//     a different `token_endpoint_auth_method`.
type Method interface {
	Name() MethodName
	Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error)
}

// Authenticator dispatches an incoming request through every registered
// Method in priority order and returns the first successful Result.
type Authenticator struct {
	methods []Method
	lookup  ClientLookup
}

// NewAuthenticator wires the canonical method set in the order keyforge
// evaluates them. Order matters: Basic auth credentials and form-post
// credentials are inspected before private_key_jwt and mTLS detection, but
// public-client detection runs last (so a missing client_secret on a
// confidential client never silently downgrades to `none`).
func NewAuthenticator(lookup ClientLookup, methods ...Method) *Authenticator {
	return &Authenticator{
		lookup:  lookup,
		methods: methods,
	}
}

// Authenticate iterates the configured methods, returning the first
// successful Result. If a method matches its detection criteria but the
// credential is invalid, that error is returned immediately — we do not
// fall through to weaker methods.
func (a *Authenticator) Authenticate(ctx context.Context, r *http.Request) (*Result, error) {
	var lastDetectedErr error
	for _, m := range a.methods {
		res, err := m.Authenticate(ctx, r, a.lookup)
		switch {
		case err == nil:
			return res, nil
		case errors.Is(err, ErrUnknownClient):
			// criteria didn't match this method; try the next
			continue
		case errors.Is(err, ErrInvalidClient),
			errors.Is(err, ErrMethodMismatch):
			// detected the credential but it failed validation; stop here
			return nil, err
		default:
			// transient error; remember it but keep trying others
			lastDetectedErr = err
		}
	}
	if lastDetectedErr != nil {
		return nil, fmt.Errorf("clientauth: no method authenticated: %w", lastDetectedErr)
	}
	return nil, ErrUnknownClient
}

// FormClientID extracts the client_id from the URL-encoded form body if
// present. It is a helper several Method implementations need to call after
// a parse-body step.
func FormClientID(r *http.Request) string {
	return r.PostFormValue("client_id")
}
