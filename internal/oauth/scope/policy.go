package scope

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by policy resolution.
var (
	ErrInvalidScope     = errors.New("scope: requested scope not permitted for this client")
	ErrInvalidResource  = errors.New("scope: requested resource not permitted for this client")
	ErrEmptyAfterFilter = errors.New("scope: no scopes remained after policy filter")
)

// Policy resolves the effective scope set and audience list for a single
// token issuance, given the client's static permissions and the request's
// requested scopes / resources.
type Policy struct {
	q *db.Queries
}

// NewPolicy wraps a sqlc Queries.
func NewPolicy(q *db.Queries) *Policy { return &Policy{q: q} }

// ResolveScopes returns the intersection of `requested` (parsed from the
// request) with `allowed` (the client's registered scope list). If the
// client has no scopes registered, `requested` is returned unchanged
// (open-by-default for backwards compatibility with bare OAuth 2.0).
//
// If `requested` is empty, the full `allowed` set is returned. Both
// outcomes preserve registration order.
func (Policy) ResolveScopes(requested, allowed []string) ([]string, error) {
	if len(requested) == 0 {
		out := make([]string, 0, len(allowed))
		out = append(out, allowed...)
		return out, nil
	}
	if len(allowed) == 0 {
		out := make([]string, 0, len(requested))
		out = append(out, requested...)
		return out, nil
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allow[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := allow[s]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrInvalidScope, s)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, ErrEmptyAfterFilter
	}
	return out, nil
}

// ResolveAudiences validates the requested RFC 8707 `resource` parameter
// values against the client's allowlist and returns the canonical audience
// list to embed on the access token. If the client has no registered
// resources, requested resources are rejected (deny-by-default for the
// audience surface — opposite of scopes — because issuing an AT with an
// audience the client never registered for would be a confused-deputy
// hazard).
//
// `requested` may be empty; in that case the returned audience defaults to
// the client_id of the asking client (the historical OAuth behaviour).
func (p *Policy) ResolveAudiences(
	ctx context.Context,
	tenantID, clientPK uuid.UUID,
	clientID string,
	requested []string,
) ([]string, error) {
	if len(requested) == 0 {
		return []string{clientID}, nil
	}
	allowed, err := p.q.ListClientAllowedResources(ctx,
		db.ListClientAllowedResourcesParams{TenantID: tenantID, ClientID: clientPK})
	if err != nil {
		return nil, fmt.Errorf("load allowed resources: %w", err)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: client has no allowed resources but requested %v",
			ErrInvalidResource, requested)
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		allow[r] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, r := range requested {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := allow[r]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrInvalidResource, r)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return []string{clientID}, nil
	}
	return out, nil
}
