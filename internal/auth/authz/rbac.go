// Package authz mounts keyforge's RBAC middleware over the admin API.
//
// The contract: incoming requests must carry an opaque access token
// (Bearer kf_at_*) with the kf:admin scope. The middleware hashes the
// presented token, looks it up in access_tokens, and resolves the
// caller's roles + flattened permission set within the tenant context.
//
// Authorization decisions are then made by Require(perm) — fail with
// 403, never 401 (the token already proved authentication; insufficient
// scope is a different error class).
package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Identity is what the middleware injects into ctx for downstream handlers.
type Identity struct {
	UserID      uuid.UUID
	ClientID    uuid.UUID
	TenantID    uuid.UUID
	Scopes      []string
	Permissions map[string]struct{}
}

// Has returns true if the identity carries the named permission.
func (i *Identity) Has(perm string) bool {
	_, ok := i.Permissions[perm]
	return ok
}

type ctxKey struct{}

// WithIdentity stores i on ctx.
func WithIdentity(ctx context.Context, i *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, i)
}

// FromContext returns the previously-attached identity, or nil.
func FromContext(ctx context.Context) *Identity {
	if v, ok := ctx.Value(ctxKey{}).(*Identity); ok {
		return v
	}
	return nil
}

// Authenticator wraps the queries needed to resolve a bearer token to
// an Identity. It must be invoked with a tenant already pinned on ctx
// (by an upstream tenancy middleware).
type Authenticator struct {
	q *db.Queries
}

// NewAuthenticator constructs an Authenticator.
func NewAuthenticator(q *db.Queries) *Authenticator { return &Authenticator{q: q} }

// AdminScope is the scope a token must carry to talk to the admin API.
const AdminScope = "kf:admin"

// PortalScope is the scope a token must carry to talk to the user-portal API.
const PortalScope = "kf:portal"

// Errors surfaced to the HTTP layer.
var (
	ErrMissingToken      = errors.New("authz: missing bearer token")
	ErrInvalidToken      = errors.New("authz: token not recognised")
	ErrInsufficientScope = errors.New("authz: insufficient scope")
)

// Resolve looks up the bearer token and returns its identity. The
// request must already have a tenant pinned on ctx.
//
// requiredScope is the scope the token must carry (typically kf:admin
// or kf:portal). Pass "" to skip the scope check (e.g. for routes that
// rely on a permission flag alone).
func (a *Authenticator) Resolve(ctx context.Context, bearer, requiredScope string) (*Identity, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := a.q.GetAccessTokenByHash(ctx, db.GetAccessTokenByHashParams{
		TenantID: tid, TokenHash: hashToken(bearer),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if requiredScope != "" && !hasScope(tok.Scopes, requiredScope) {
		return nil, ErrInsufficientScope
	}
	id := &Identity{
		TenantID:    tid,
		ClientID:    tok.ClientID,
		Scopes:      tok.Scopes,
		Permissions: map[string]struct{}{},
	}
	if tok.UserID.Valid {
		id.UserID, _ = uuid.FromBytes(tok.UserID.Bytes[:])
		roles, rerr := a.q.ListRolesForUser(ctx, db.ListRolesForUserParams{
			TenantID: tid, UserID: id.UserID,
		})
		if rerr != nil {
			return nil, rerr
		}
		for _, r := range roles {
			for _, p := range r.Permissions {
				id.Permissions[p] = struct{}{}
			}
		}
	}
	return id, nil
}

// Middleware enforces authentication: every request below it has an
// Identity in context or has been rejected with 401/403. The token must
// carry AdminScope. Use ScopedMiddleware to require a different scope.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return a.ScopedMiddleware(AdminScope)(next)
}

// ScopedMiddleware returns a middleware that requires the named scope.
// Use authz.PortalScope for the user portal, authz.AdminScope for the
// admin console.
func (a *Authenticator) ScopedMiddleware(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := extractBearer(r)
			if bearer == "" {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			id, err := a.Resolve(r.Context(), bearer, requiredScope)
			if err != nil {
				switch {
				case errors.Is(err, ErrInvalidToken):
					http.Error(w, "invalid token", http.StatusUnauthorized)
				case errors.Is(err, ErrInsufficientScope):
					http.Error(w, "insufficient scope", http.StatusForbidden)
				default:
					http.Error(w, "auth failed", http.StatusInternalServerError)
				}
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

// Require returns a middleware that allows the request only if the
// identity carries perm.
func Require(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := FromContext(r.Context())
			if id == nil {
				http.Error(w, "not authenticated", http.StatusUnauthorized)
				return
			}
			if !id.Has(perm) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[len("Bearer "):])
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
