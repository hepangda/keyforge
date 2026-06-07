package federation

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Registry is a per-process cache of Connector instances keyed by
// (tenant_id, slug). It is safe for concurrent use.
type Registry struct {
	q   *db.Queries
	env *kcrypto.Envelope

	mu    sync.RWMutex
	cache map[string]*Connector
}

// NewRegistry constructs a Registry.
func NewRegistry(q *db.Queries, env *kcrypto.Envelope) *Registry {
	return &Registry{q: q, env: env, cache: map[string]*Connector{}}
}

func key(tenantID uuid.UUID, slug string) string { return tenantID.String() + "|" + slug }

// LookupBySlug returns the connector for (tenant, slug), loading from
// Postgres on cache miss.
func (r *Registry) LookupBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*Connector, error) {
	k := key(tenantID, slug)
	r.mu.RLock()
	c := r.cache[k]
	r.mu.RUnlock()
	if c != nil {
		return c, nil
	}
	row, err := r.q.GetIdPConnectorBySlug(ctx, db.GetIdPConnectorBySlugParams{
		TenantID: tenantID, Slug: slug,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnknownIdP, err)
	}
	if !row.Enabled {
		return nil, ErrUnknownIdP
	}
	c, err = NewConnector(row, r.env)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[k] = c
	r.mu.Unlock()
	return c, nil
}

// LookupByID is the same lookup keyed on the connector's row id (used
// when callback handlers read the federation_idp_id off auth_requests).
func (r *Registry) LookupByID(ctx context.Context, tenantID, id uuid.UUID) (*Connector, error) {
	row, err := r.q.GetIdPConnectorByID(ctx, db.GetIdPConnectorByIDParams{
		ID: id, TenantID: tenantID,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnknownIdP, err)
	}
	return r.LookupBySlug(ctx, tenantID, row.Slug)
}

// Enabled returns all enabled connectors in the current tenant, used by
// the login page to render IdP buttons. It does NOT cache the list — the
// underlying SQL is cheap and we want the page to reflect admin toggles
// immediately.
func (r *Registry) Enabled(ctx context.Context, tenantID uuid.UUID) ([]*Connector, error) {
	rows, err := r.q.ListEnabledIdPConnectors(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]*Connector, 0, len(rows))
	for _, row := range rows {
		c, err := NewConnector(row, r.env)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// Invalidate drops a single (tenant, slug) entry from the cache. Use
// after an admin update.
func (r *Registry) Invalidate(tenantID uuid.UUID, slug string) {
	r.mu.Lock()
	delete(r.cache, key(tenantID, slug))
	r.mu.Unlock()
}

// EnsureTenantCtx is a helper for handlers: it wraps ctx with tenantID
// so downstream queries pass tenant guards.
func EnsureTenantCtx(ctx context.Context, tenantID uuid.UUID) context.Context {
	return postgres.ContextWithTenant(ctx, tenantID)
}
