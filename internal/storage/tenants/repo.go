// Package tenants is the tenant-scoped repository for tenant records.
//
// Each keyforge installation is multi-tenant: every domain entity belongs to
// exactly one tenant. This package owns the lifecycle of tenants themselves
// (no parent), so it does not call MustTenant — callers identify tenants by
// id, slug, or issuer directly.
package tenants

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// ErrNotFound is returned when a lookup does not match any tenant.
var ErrNotFound = errors.New("tenant not found")

// Tenant is the domain-shaped projection of a row in tenants.
type Tenant struct {
	ID          uuid.UUID
	Slug        string
	DisplayName string
	Issuer      string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Repository wraps the sqlc Queries with domain-shaped reads/writes.
type Repository struct {
	q *db.Queries
}

// New constructs a Repository against a pgxpool.
func New(pool *pgxpool.Pool) *Repository { return &Repository{q: db.New(pool)} }

// FromQueries lets transactional code bind a repository to its own *db.Queries.
func FromQueries(q *db.Queries) *Repository { return &Repository{q: q} }

// Create inserts a tenant.
func (r *Repository) Create(ctx context.Context, slug, displayName, issuer string) (*Tenant, error) {
	row, err := r.q.CreateTenant(ctx, db.CreateTenantParams{
		Slug:        slug,
		DisplayName: displayName,
		Issuer:      issuer,
	})
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	return toDomain(row), nil
}

// GetByID looks up a tenant by primary key.
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	row, err := r.q.GetTenantByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get tenant by id: %w", err)
	}
	return toDomain(row), nil
}

// GetBySlug looks up a tenant by slug.
func (r *Repository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	row, err := r.q.GetTenantBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get tenant by slug: %w", err)
	}
	return toDomain(row), nil
}

// GetByIssuer looks up a tenant by its OIDC issuer URL.
func (r *Repository) GetByIssuer(ctx context.Context, issuer string) (*Tenant, error) {
	row, err := r.q.GetTenantByIssuer(ctx, issuer)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get tenant by issuer: %w", err)
	}
	return toDomain(row), nil
}

// List returns up to limit tenants ordered by created_at desc.
func (r *Repository) List(ctx context.Context, limit, offset int32) ([]*Tenant, error) {
	rows, err := r.q.ListTenants(ctx, db.ListTenantsParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	out := make([]*Tenant, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomain(row))
	}
	return out, nil
}

// Update applies non-identity edits to a tenant.
func (r *Repository) Update(ctx context.Context, t *Tenant) (*Tenant, error) {
	row, err := r.q.UpdateTenant(ctx, db.UpdateTenantParams{
		ID:          t.ID,
		DisplayName: t.DisplayName,
		Issuer:      t.Issuer,
		Enabled:     t.Enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	return toDomain(row), nil
}

// Delete removes a tenant. ON DELETE CASCADE clears every dependent row.
func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.q.DeleteTenant(ctx, id); err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	return nil
}

func toDomain(row *db.Tenant) *Tenant {
	return &Tenant{
		ID:          row.ID,
		Slug:        row.Slug,
		DisplayName: row.DisplayName,
		Issuer:      row.Issuer,
		Enabled:     row.Enabled,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}
