package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrNoTenant is returned by MustTenant when there is no tenant in context.
var ErrNoTenant = errors.New("no tenant id in context")

// TenantCtxKey is the context value key carrying the current tenant ID.
// Use ContextWithTenant / TenantFromContext / MustTenant rather than reading
// the key directly so the storage layer can change representation freely.
type tenantCtxKey struct{}

// ContextWithTenant returns a copy of ctx that carries tid as the active
// tenant. Storage methods read this via TenantFromContext.
func ContextWithTenant(ctx context.Context, tid uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tid)
}

// TenantFromContext returns the tenant id stored in ctx and whether one was
// present.
func TenantFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(tenantCtxKey{}).(uuid.UUID)
	return v, ok
}

// MustTenant returns the tenant in ctx or ErrNoTenant. Repository methods
// call this to enforce that every query is tenant-scoped: forgetting to
// inject a tenant becomes an obvious runtime failure during testing, not a
// silent cross-tenant read.
func MustTenant(ctx context.Context) (uuid.UUID, error) {
	tid, ok := TenantFromContext(ctx)
	if !ok {
		return uuid.Nil, ErrNoTenant
	}
	return tid, nil
}
