//go:build integration

package portal_test

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

	"github.com/hepangda/keyforge/internal/audit"
	"github.com/hepangda/keyforge/internal/auth/authz"
	"github.com/hepangda/keyforge/internal/auth/mfa"
	"github.com/hepangda/keyforge/internal/auth/password"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	portal "github.com/hepangda/keyforge/internal/portal/api"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

type portalRig struct {
	q            *db.Queries
	sessionStore session.Store
	router       *chi.Mux
	tenant       uuid.UUID
	userA        uuid.UUID
	userB        uuid.UUID
	tokenA       string
	tokenB       string
	tokenNoScope string
}

func mintAT(t *testing.T, q *db.Queries, ctx context.Context, tid, uid, cid uuid.UUID, scopes []string) string {
	t.Helper()
	tok := "kf_at_" + uuid.NewString()
	hash := sha256.Sum256([]byte(tok))
	if _, err := q.InsertAccessToken(ctx, db.InsertAccessTokenParams{
		TenantID:  tid,
		TokenHash: hex.EncodeToString(hash[:]),
		ClientID:  cid,
		UserID:    pgtype.UUID{Bytes: uid, Valid: true},
		Scopes:    scopes,
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert AT: %v", err)
	}
	return tok
}

func buildPortalRig(t *testing.T) *portalRig {
	t.Helper()
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)

	tenant, err := q.CreateTenant(ctx, db.CreateTenantParams{
		Slug: "portal", DisplayName: "Portal Test", Issuer: "https://p.test",
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	tid := tenant.ID
	ctxT := postgres.ContextWithTenant(ctx, tid)

	userA, err := q.CreateUser(ctxT, db.CreateUserParams{
		TenantID: tid, Email: "alice@p.test", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("user A: %v", err)
	}
	userB, err := q.CreateUser(ctxT, db.CreateUserParams{
		TenantID: tid, Email: "bob@p.test", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("user B: %v", err)
	}

	// Seed alice's password so the change-password test has something to verify against.
	hash, err := password.Hash("alice-initial-pw", password.DefaultParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := q.UpsertUserCredentials(ctxT, db.UpsertUserCredentialsParams{
		UserID: userA.ID, TenantID: tid, PasswordHash: hash, Algorithm: "argon2id",
	}); err != nil {
		t.Fatalf("upsert cred: %v", err)
	}

	cli, err := q.CreateClient(ctxT, db.CreateClientParams{
		TenantID:                tid,
		ClientID:                "portal-spa",
		ClientType:              "public",
		Name:                    "Portal SPA",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{authz.PortalScope},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	tokenA := mintAT(t, q, ctxT, tid, userA.ID, cli.ID, []string{authz.PortalScope})
	tokenB := mintAT(t, q, ctxT, tid, userB.ID, cli.ID, []string{authz.PortalScope})
	tokenNoScope := mintAT(t, q, ctxT, tid, userA.ID, cli.ID, []string{"openid"})

	usersRepo := users.New(fx.Pool)
	sStore := session.NewPostgresStore(fx.Pool)
	auditor := audit.NewRecorder(audit.NewPostgresSink(q), slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Envelope for TOTP enroll.
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	env, _ := kcrypto.NewEnvelope(kek)

	router := chi.NewRouter()
	portal.New(portal.Config{
		Queries:       q,
		UsersRepo:     usersRepo,
		SessionStore:  sStore,
		TOTP:          mfa.NewTOTP(q, env, "keyforge"),
		Recovery:      mfa.NewRecovery(q),
		Auditor:       auditor,
		Authenticator: authz.NewAuthenticator(q),
		TenantFor:     func(_ *http.Request) (uuid.UUID, error) { return tid, nil },
	}).Mount(router, "/portal/api/v1")

	return &portalRig{
		q: q, sessionStore: sStore, router: router,
		tenant: tid, userA: userA.ID, userB: userB.ID,
		tokenA: tokenA, tokenB: tokenB, tokenNoScope: tokenNoScope,
	}
}

func (r *portalRig) do(t *testing.T, method, path, token string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewBuffer(b)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.router.ServeHTTP(w, req)
	return w.Result()
}

func TestPortalNoTokenIsUnauthorized(t *testing.T) {
	r := buildPortalRig(t)
	resp := r.do(t, "GET", "/portal/api/v1/me", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPortalRejectsTokenWithoutPortalScope(t *testing.T) {
	r := buildPortalRig(t)
	resp := r.do(t, "GET", "/portal/api/v1/me", r.tokenNoScope, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPortalMeReturnsCallerProfile(t *testing.T) {
	r := buildPortalRig(t)
	resp := r.do(t, "GET", "/portal/api/v1/me", r.tokenA, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["email"] != "alice@p.test" {
		t.Fatalf("email=%v", got["email"])
	}
}

func TestPortalRevokeOtherUsersSession404(t *testing.T) {
	r := buildPortalRig(t)
	// Open a session for user B.
	ctx := postgres.ContextWithTenant(context.Background(), r.tenant)
	sess, err := r.sessionStore.Create(ctx, session.CreateInput{
		UserID: r.userB, TTL: time.Hour, MFALevel: "pwd", AMR: []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	// User A's token must NOT be able to revoke B's session.
	resp := r.do(t, "DELETE", "/portal/api/v1/sessions/"+sess.ID.String(), r.tokenA, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPortalChangePasswordRoundTrip(t *testing.T) {
	r := buildPortalRig(t)
	resp := r.do(t, "POST", "/portal/api/v1/password", r.tokenA, map[string]string{
		"current_password": "alice-initial-pw",
		"new_password":     "alice-new-pw-xyz",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	// Wrong current password fails.
	resp2 := r.do(t, "POST", "/portal/api/v1/password", r.tokenA, map[string]string{
		"current_password": "alice-initial-pw",
		"new_password":     "another-fresh-pw",
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong-current status=%d", resp2.StatusCode)
	}
}

func TestPortalRecoveryCodeRegenerate(t *testing.T) {
	r := buildPortalRig(t)
	resp := r.do(t, "POST", "/portal/api/v1/mfa/recovery/regenerate", r.tokenA, struct{}{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	codes, ok := got["codes"].([]any)
	if !ok || len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("codes=%v", got["codes"])
	}
}

func TestPortalDeleteAccountSoftDeletes(t *testing.T) {
	r := buildPortalRig(t)
	resp := r.do(t, "DELETE", "/portal/api/v1/me", r.tokenB, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	// GetUserByID filters deleted_at IS NULL — its absence confirms the
	// soft-delete took effect.
	ctx := postgres.ContextWithTenant(context.Background(), r.tenant)
	if _, err := r.q.GetUserByID(ctx, db.GetUserByIDParams{ID: r.userB, TenantID: r.tenant}); err == nil {
		t.Fatalf("expected soft-deleted user to be filtered out")
	}
}
