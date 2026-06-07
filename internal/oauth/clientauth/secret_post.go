package clientauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/hepangda/keyforge/internal/storage/clients"
)

// SecretPostMethod authenticates clients that send client_id+client_secret in
// the application/x-www-form-urlencoded request body.
//
// RFC 6749 §2.3.1 marks this method NOT RECOMMENDED in favour of HTTP Basic,
// but many legacy clients still rely on it; keyforge keeps it for
// compatibility and registers it explicitly per-client.
type SecretPostMethod struct{}

// NewSecretPostMethod constructs the method.
func NewSecretPostMethod() *SecretPostMethod { return &SecretPostMethod{} }

// Name implements Method.
func (SecretPostMethod) Name() MethodName { return MethodSecretPost }

// Authenticate implements Method.
func (SecretPostMethod) Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error) {
	clientID := FormClientID(r)
	secret := r.PostFormValue("client_secret")
	if clientID == "" || secret == "" {
		return nil, ErrUnknownClient
	}
	cli, err := lookup.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	if cli.TokenEndpointAuthMethod != string(MethodSecretPost) {
		return nil, ErrMethodMismatch
	}
	if err := VerifySecret(cli.ClientSecretHash, secret); err != nil {
		return nil, ErrInvalidClient
	}
	return &Result{Client: cli, Method: MethodSecretPost}, nil
}
