package clientauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/hepangda/keyforge/internal/storage/clients"
)

// SecretBasicMethod authenticates clients using RFC 6749 §2.3.1 HTTP Basic.
type SecretBasicMethod struct{}

// NewSecretBasicMethod constructs the method.
func NewSecretBasicMethod() *SecretBasicMethod { return &SecretBasicMethod{} }

// Name implements Method.
func (SecretBasicMethod) Name() MethodName { return MethodSecretBasic }

// Authenticate implements Method.
func (SecretBasicMethod) Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error) {
	rawUser, rawPass, ok := r.BasicAuth()
	if !ok {
		return nil, ErrUnknownClient
	}
	// RFC 6749 §2.3.1 requires the credentials to be percent-encoded before
	// Basic encoding. Older OAuth clients commonly emit the raw form, so we
	// accept either.
	clientID, err := url.PathUnescape(rawUser)
	if err != nil || clientID == "" {
		clientID = rawUser
	}
	secret, err := url.PathUnescape(rawPass)
	if err != nil {
		secret = rawPass
	}

	cli, err := lookup.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	if cli.TokenEndpointAuthMethod != string(MethodSecretBasic) {
		return nil, ErrMethodMismatch
	}
	if err := VerifySecret(cli.ClientSecretHash, secret); err != nil {
		return nil, ErrInvalidClient
	}
	return &Result{Client: cli, Method: MethodSecretBasic}, nil
}
