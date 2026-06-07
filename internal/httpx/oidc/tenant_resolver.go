package oidc

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hepangda/keyforge/internal/storage/tenants"
)

// TenantResolver returns the active tenant for a given request. The
// production resolver matches request host against tenant issuer URLs; the
// global-default resolver always returns the bootstrap tenant.
type TenantResolver interface {
	Resolve(ctx context.Context, r *http.Request) (*tenants.Tenant, error)
}

// DefaultTenantResolver always returns a single tenant, looked up by slug
// at request time (so the cached value remains coherent if the tenant is
// edited).
type DefaultTenantResolver struct {
	Repo *tenants.Repository
	Slug string
}

// NewDefaultTenantResolver constructs the resolver. Slug defaults to
// "default" (the bootstrap tenant from migrations/0002).
func NewDefaultTenantResolver(repo *tenants.Repository, slug string) *DefaultTenantResolver {
	if slug == "" {
		slug = "default"
	}
	return &DefaultTenantResolver{Repo: repo, Slug: slug}
}

// Resolve implements TenantResolver.
func (r *DefaultTenantResolver) Resolve(ctx context.Context, _ *http.Request) (*tenants.Tenant, error) {
	return r.Repo.GetBySlug(ctx, r.Slug)
}

// IssuerTenantResolver matches the request's Host (and optional path
// prefix) against each tenant's issuer URL. Used by multi-tenant
// deployments that front each tenant on a distinct hostname.
type IssuerTenantResolver struct {
	Repo *tenants.Repository
}

// NewIssuerTenantResolver constructs the resolver.
func NewIssuerTenantResolver(repo *tenants.Repository) *IssuerTenantResolver {
	return &IssuerTenantResolver{Repo: repo}
}

// Resolve implements TenantResolver.
func (r *IssuerTenantResolver) Resolve(ctx context.Context, req *http.Request) (*tenants.Tenant, error) {
	scheme := "https"
	if req.TLS == nil {
		scheme = "http"
	}
	issuer := scheme + "://" + req.Host
	return r.Repo.GetByIssuer(ctx, issuer)
}

// writeJSON writes a JSON body and content-type header. Errors writing to
// the response body are intentionally ignored — the client has likely
// disconnected.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
