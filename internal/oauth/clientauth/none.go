package clientauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/hepangda/keyforge/internal/storage/clients"
)

// NoneMethod authenticates public clients that present only a client_id
// (no secret, no client assertion, no mTLS). It is detected last so that
// missing credentials on a confidential client cannot be misclassified.
type NoneMethod struct{}

// NewNoneMethod constructs the NoneMethod.
func NewNoneMethod() *NoneMethod { return &NoneMethod{} }

// Name implements Method.
func (NoneMethod) Name() MethodName { return MethodNone }

// Authenticate implements Method.
func (NoneMethod) Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error) {
	clientID := FormClientID(r)
	if clientID == "" {
		return nil, ErrUnknownClient
	}
	// If the request also presents a secret or assertion, this is not a
	// `none`-method request.
	if r.PostFormValue("client_secret") != "" || r.PostFormValue("client_assertion") != "" {
		return nil, ErrUnknownClient
	}
	if u, p, ok := r.BasicAuth(); ok && (u != "" || p != "") {
		return nil, ErrUnknownClient
	}

	cli, err := lookup.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return nil, ErrUnknownClient
		}
		return nil, err
	}
	if cli.TokenEndpointAuthMethod != string(MethodNone) {
		return nil, ErrMethodMismatch
	}
	if cli.ClientType != clients.TypePublic {
		return nil, ErrMethodMismatch
	}
	return &Result{Client: cli, Method: MethodNone}, nil
}
