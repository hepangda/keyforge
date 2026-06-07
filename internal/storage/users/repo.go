// Package users is the tenant-scoped repository for end-user accounts and
// their stored credentials.
//
// Every method on Repository requires a tenant id in ctx (via
// postgres.ContextWithTenant). Repositories return *ErrNoTenant when ctx is
// missing one, which surfaces forgotten tenant scoping as an obvious runtime
// failure rather than a silent cross-tenant read.
package users

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// ErrNotFound is returned when a lookup does not match any user in the
// current tenant.
var ErrNotFound = errors.New("user not found")

// User is the domain-shaped projection of a row in users.
type User struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	Email         string
	EmailVerified bool
	DisplayName   string
	Locale        string
	Zoneinfo      string
	PictureURL    string
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}

// Credential is the domain-shaped projection of a row in user_credentials.
type Credential struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	PasswordHash string
	Algorithm    string
	MustChange   bool
	UpdatedAt    time.Time
}

// Repository wraps the sqlc Queries.
type Repository struct {
	q *db.Queries
}

// New constructs a Repository against a pgxpool.
func New(pool *pgxpool.Pool) *Repository { return &Repository{q: db.New(pool)} }

// FromQueries lets transactional code bind a repository to its own *db.Queries.
func FromQueries(q *db.Queries) *Repository { return &Repository{q: q} }

// CreateInput captures the required fields for inserting a new user.
type CreateInput struct {
	Email         string
	EmailVerified bool
	DisplayName   string
	Locale        string
	Zoneinfo      string
}

// Create inserts a new user in the current tenant.
func (r *Repository) Create(ctx context.Context, in CreateInput) (*User, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.CreateUser(ctx, db.CreateUserParams{
		TenantID:      tid,
		Email:         in.Email,
		EmailVerified: in.EmailVerified,
		DisplayName:   text(in.DisplayName),
		Locale:        text(in.Locale),
		Zoneinfo:      text(in.Zoneinfo),
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return toDomain(row), nil
}

// GetByID returns the user with this id in the current tenant, or
// ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.GetUserByID(ctx, db.GetUserByIDParams{ID: id, TenantID: tid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return toDomain(row), nil
}

// GetByEmail finds a user by case-insensitive email match in the current
// tenant.
func (r *Repository) GetByEmail(ctx context.Context, email string) (*User, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.GetUserByEmail(ctx, db.GetUserByEmailParams{TenantID: tid, Lower: email})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return toDomain(row), nil
}

// List returns up to limit non-deleted users in the current tenant ordered by
// most recent first.
func (r *Repository) List(ctx context.Context, limit, offset int32) ([]*User, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListUsersByTenant(ctx, db.ListUsersByTenantParams{
		TenantID: tid, Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	out := make([]*User, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomain(row))
	}
	return out, nil
}

// SoftDelete sets deleted_at and disables the user; the jobs/hard_delete
// worker removes the row 30 days later.
func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	return r.q.SoftDeleteUser(ctx, db.SoftDeleteUserParams{ID: id, TenantID: tid})
}

// UpsertCredential stores or replaces a user's password hash. The credential
// is required to be in the same tenant as the user; the database FK enforces
// this.
func (r *Repository) UpsertCredential(ctx context.Context, c Credential) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	if c.TenantID != uuid.Nil && c.TenantID != tid {
		return fmt.Errorf("credential tenant_id %s does not match ctx tenant %s", c.TenantID, tid)
	}
	algo := c.Algorithm
	if algo == "" {
		algo = "argon2id"
	}
	return r.q.UpsertUserCredentials(ctx, db.UpsertUserCredentialsParams{
		UserID:       c.UserID,
		TenantID:     tid,
		PasswordHash: c.PasswordHash,
		Algorithm:    algo,
		MustChange:   c.MustChange,
	})
}

// GetCredential returns the stored credential for a user, or ErrNotFound.
func (r *Repository) GetCredential(ctx context.Context, userID uuid.UUID) (*Credential, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.GetUserCredentials(ctx, db.GetUserCredentialsParams{
		UserID: userID, TenantID: tid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user credentials: %w", err)
	}
	return &Credential{
		UserID:       row.UserID,
		TenantID:     row.TenantID,
		PasswordHash: row.PasswordHash,
		Algorithm:    row.Algorithm,
		MustChange:   row.MustChange,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

func toDomain(row *db.User) *User {
	u := &User{
		ID:            row.ID,
		TenantID:      row.TenantID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		DisplayName:   textValue(row.DisplayName),
		Locale:        textValue(row.Locale),
		Zoneinfo:      textValue(row.Zoneinfo),
		PictureURL:    textValue(row.PictureUrl),
		Enabled:       row.Enabled,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
	if row.DeletedAt.Valid {
		t := row.DeletedAt.Time
		u.DeletedAt = &t
	}
	return u
}

func text(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func textValue(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
