//go:build integration

package admin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/admin"
	"github.com/hepangda/keyforge/internal/audit"
	"github.com/hepangda/keyforge/internal/auth/authz"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

type adminRig struct {
	q            *db.Queries
	sessionStore session.Store
	router       *chi.Mux
	tenantA      uuid.UUID
	tenantB      uuid.UUID
	adminUserA   uuid.UUID
	clientA      uuid.UUID
	atTokenA     string
}

func buildRig(t *testing.T) *adminRig {
	t.Helper()
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)

	ta, err := q.CreateTenant(ctx, db.CreateTenantParams{Slug: "a", DisplayName: "A", Issuer: "https://a.test"})
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	tb, err := q.CreateTenant(ctx, db.CreateTenantParams{Slug: "b", DisplayName: "B", Issuer: "https://b.test"})
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}

	ctxA := postgres.ContextWithTenant(ctx, ta.ID)
	adminUser, err := q.CreateUser(ctxA, db.CreateUserParams{
		TenantID: ta.ID, Email: "admin@a.test", EmailVerified: true,
		DisplayName: pgtype.Text{String: "Admin", Valid: true},
	})
	if err != nil {
		t.Fatalf("admin user: %v", err)
	}
	role, err := q.GetRoleByName(ctx, "tenant_admin")
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if err := q.GrantRole(ctxA, db.GrantRoleParams{
		TenantID: ta.ID, UserID: adminUser.ID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Seed a client for the admin AT.
	cli, err := q.CreateClient(ctxA, db.CreateClientParams{
		TenantID:                ta.ID,
		ClientID:                "admin-cli",
		ClientType:              "confidential",
		Name:                    "admin-cli",
		GrantTypes:              []string{"client_credentials"},
		ResponseTypes:           []string{},
		ResponseModes:           []string{},
		Scopes:                  []string{authz.AdminScope},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	// Mint an admin AT with kf:admin scope so the middleware accepts it.
	rawAT := "kf_at_admin_" + uuid.NewString()
	atHash := sha256.Sum256([]byte(rawAT))
	if _, err := q.InsertAccessToken(ctxA, db.InsertAccessTokenParams{
		TenantID:  ta.ID,
		TokenHash: hex.EncodeToString(atHash[:]),
		ClientID:  cli.ID,
		UserID:    pgtype.UUID{Bytes: adminUser.ID, Valid: true},
		Scopes:    []string{authz.AdminScope},
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create AT: %v", err)
	}

	usersRepo := users.New(fx.Pool)
	sStore := session.NewPostgresStore(fx.Pool)
	auditor := audit.NewRecorder(audit.NewPostgresSink(q), slog.New(slog.NewTextHandler(io.Discard, nil)))

	tenantFor := func(r *http.Request) (uuid.UUID, error) {
		header := r.Header.Get("X-Test-Tenant")
		if header == "" {
			return ta.ID, nil
		}
		return uuid.Parse(header)
	}

	router := chi.NewRouter()
	admin.New(admin.Config{
		Queries:       q,
		UsersRepo:     usersRepo,
		SessionStore:  sStore,
		Auditor:       auditor,
		Authenticator: authz.NewAuthenticator(q),
		TenantFor:     tenantFor,
	}).Mount(router, "/admin/api/v1")

	return &adminRig{
		q:            q,
		sessionStore: sStore,
		router:       router,
		tenantA:      ta.ID,
		tenantB:      tb.ID,
		adminUserA:   adminUser.ID,
		clientA:      cli.ID,
		atTokenA:     rawAT,
	}
}

func (r *adminRig) do(t *testing.T, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewBuffer(buf)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+r.atTokenA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.router.ServeHTTP(w, req)
	return w.Result()
}

func TestAdminMissingTokenIsUnauthorized(t *testing.T) {
	r := buildRig(t)
	req := httptest.NewRequest("GET", "/admin/api/v1/audit", nil)
	w := httptest.NewRecorder()
	r.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestAdminGrantRoleRecordsAudit(t *testing.T) {
	r := buildRig(t)
	// Create a target user in tenant A.
	ctxA := postgres.ContextWithTenant(context.Background(), r.tenantA)
	target, err := r.q.CreateUser(ctxA, db.CreateUserParams{
		TenantID: r.tenantA, Email: "target@a.test", EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("target: %v", err)
	}

	resp := r.do(t, "POST", "/admin/api/v1/users/"+target.ID.String()+"/roles",
		map[string]string{"role_name": "tenant_admin"}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("grant status=%d body=%s", resp.StatusCode, body)
	}

	roles, err := r.q.ListRolesForUser(ctxA, db.ListRolesForUserParams{
		TenantID: r.tenantA, UserID: target.ID,
	})
	if err != nil || len(roles) != 1 {
		t.Fatalf("roles: err=%v roles=%v", err, roles)
	}

	rows, err := r.q.ListAuditEvents(ctxA, db.ListAuditEventsParams{
		TenantID:   r.tenantA,
		OccurredAt: time.Now().Add(time.Hour),
		Limit:      50,
	})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found bool
	for _, e := range rows {
		if e.Action == "role.grant" && e.TargetID.String == target.ID.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit event missing")
	}
}

func TestAdminCrossTenantIsolation(t *testing.T) {
	r := buildRig(t)
	// Create a user in tenant B (different tenant). Admin token is for A.
	ctxB := postgres.ContextWithTenant(context.Background(), r.tenantB)
	target, err := r.q.CreateUser(ctxB, db.CreateUserParams{
		TenantID: r.tenantB, Email: "bob@b.test", EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}

	// Hitting B's tenant context with A's AT should reject the token
	// at lookup (the AT row is scoped to A; B's query finds nothing).
	resp := r.do(t, "GET", "/admin/api/v1/users/"+target.ID.String()+"/roles", nil,
		map[string]string{"X-Test-Tenant": r.tenantB.String()})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 cross-tenant, got %d %s", resp.StatusCode, body)
	}
}

func TestAdminMissingPermissionForbidden(t *testing.T) {
	r := buildRig(t)
	// Strip the tenant_admin role; now the user has nothing.
	role, _ := r.q.GetRoleByName(context.Background(), "tenant_admin")
	ctxA := postgres.ContextWithTenant(context.Background(), r.tenantA)
	if err := r.q.RevokeRole(ctxA, db.RevokeRoleParams{
		TenantID: r.tenantA, UserID: r.adminUserA, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	resp := r.do(t, "GET", "/admin/api/v1/audit", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}
