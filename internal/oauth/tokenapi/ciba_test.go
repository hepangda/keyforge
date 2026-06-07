//go:build integration

package tokenapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/auth/password"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/oauth/ciba"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/tokenapi"
	"github.com/hepangda/keyforge/internal/oauth/tokens"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

type cibaRig struct {
	tenant *tenants.Tenant
	client *clients.Client
	user   *users.User
	srv    *httptest.Server
	q      *db.Queries
}

func setupCIBA(t *testing.T) *cibaRig {
	t.Helper()
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	tenantsRepo := tenants.New(fx.Pool)
	tenant, err := tenantsRepo.Create(ctx, "ciba", "CIBA", "https://ciba.test")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	clientsRepo := clients.New(fx.Pool)
	hash, _ := clientauth.HashSecret("ciba-secret")
	cli, err := clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "ciba-rp",
		ClientType:              clients.TypeConfidential,
		Name:                    "CIBA RP",
		ClientSecretHash:        hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
		GrantTypes:              []string{ciba.GrantType},
		Scopes:                  []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatal(err)
	}

	usersRepo := users.New(fx.Pool)
	user, err := usersRepo.Create(ctxT, users.CreateInput{
		Email: "ciba-user@ciba.test", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pHash, _ := password.Hash("hunter22", password.DefaultParams())
	if err := usersRepo.UpsertCredential(ctxT, users.Credential{
		UserID: user.ID, PasswordHash: pHash,
	}); err != nil {
		t.Fatal(err)
	}

	env, _ := kcrypto.NewEnvelope(make([]byte, 32))
	store := jwks.NewPostgresStore(fx.Pool, env, jwks.SystemClock())
	if _, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig); err != nil {
		t.Fatal(err)
	}
	signer := jwks.NewSigner(store)

	tenantFor := func(*http.Request) (uuid.UUID, error) { return tenant.ID, nil }

	issuer, err := tokens.NewIssuer(tokens.Config{
		Pool: fx.Pool, Signer: signer, UsersRepo: usersRepo,
		Issuer: "https://ciba.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := clientauth.NewAuthenticator(
		&clientLookup{repo: clientsRepo, tid: tenant.ID, pool: fx.Pool},
		clientauth.NewSecretBasicMethod(),
	)

	tokenH, err := tokenapi.New(tokenapi.Config{
		Queries:               db.New(fx.Pool),
		Issuer:                issuer,
		Authenticator:         auth,
		ClientsRepo:           clientsRepo,
		UsersRepo:             usersRepo,
		TenantFor:             tenantFor,
		DevicePollMinInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	cibaH, err := ciba.New(ciba.Config{
		Queries:       db.New(fx.Pool),
		Authenticator: auth,
		UsersRepo:     usersRepo,
		TenantFor:     tenantFor,
		TTL:           30 * time.Second,
		PollInterval:  200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	tokenH.Routes(mux)
	cibaH.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &cibaRig{
		tenant: tenant, client: cli, user: user,
		srv: srv, q: db.New(fx.Pool),
	}
}

// pendingCIBAID is a helper that pulls the ID of the first pending CIBA
// request for the given user.
func pendingCIBAID(t *testing.T, q *db.Queries, tenantID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	rows, err := q.ListPendingCIBAForUser(context.Background(),
		db.ListPendingCIBAForUserParams{
			TenantID: tenantID,
			UserID:   pgtypeUUID(userID),
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no pending CIBA requests found")
	}
	return rows[0].ID
}

func TestCIBAFlowHappyPath(t *testing.T) {
	r := setupCIBA(t)

	// 1) Client posts /bc-authorize with login_hint to identify the user.
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/bc-authorize",
		strings.NewReader(url.Values{
			"login_hint":      {r.user.Email},
			"scope":           {"openid profile"},
			"binding_message": {"Approve sign-in to Acme CRM"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.client.ClientID, "ciba-secret")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("bc-authorize status %d: %s", rsp.StatusCode, body)
	}
	var ar ciba.AuthorizeResponse
	_ = json.Unmarshal(body, &ar)
	if ar.AuthReqID == "" {
		t.Fatalf("missing auth_req_id: %+v", ar)
	}

	// 2) Poll /oauth/token before approval — expect authorization_pending.
	poll := func() (int, []byte) {
		t.Helper()
		preq, _ := http.NewRequestWithContext(context.Background(),
			http.MethodPost, r.srv.URL+"/oauth/token",
			strings.NewReader(url.Values{
				"grant_type":  {ciba.GrantType},
				"auth_req_id": {ar.AuthReqID},
			}.Encode()))
		preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		preq.SetBasicAuth(r.client.ClientID, "ciba-secret")
		prsp, perr := http.DefaultClient.Do(preq)
		if perr != nil {
			t.Fatal(perr)
		}
		pbody, _ := io.ReadAll(prsp.Body)
		_ = prsp.Body.Close()
		return prsp.StatusCode, pbody
	}

	pstatus, pbody := poll()
	if !strings.Contains(string(pbody), "authorization_pending") {
		t.Fatalf("expected authorization_pending, got %d %s", pstatus, pbody)
	}

	// 3) Simulate user approval out-of-band (in production this is the
	// user portal's "approve sign-in" page).
	id := pendingCIBAID(t, r.q, r.tenant.ID, r.user.ID)
	if err := ciba.Approve(context.Background(), r.q, r.tenant.ID, id); err != nil {
		t.Fatal(err)
	}

	// 4) Poll again after the announced interval — expect token issuance.
	time.Sleep(250 * time.Millisecond)
	status2, pbody2 := poll()
	if status2 != http.StatusOK {
		t.Fatalf("token poll after approval: status %d body %s",
			status2, pbody2)
	}
	var tr tokens.Response
	_ = json.Unmarshal(pbody2, &tr)
	if tr.AccessToken == "" {
		t.Fatalf("missing access_token: %s", pbody2)
	}
	if tr.IDToken == "" {
		t.Errorf("expected id_token for openid scope")
	}

	// 5) Same auth_req_id consumed — second poll must fail.
	statusAgain, againBody := poll()
	if statusAgain == http.StatusOK {
		t.Errorf("CIBA auth_req_id replay should fail; got %s", againBody)
	}
}

func TestCIBAFlowDenied(t *testing.T) {
	r := setupCIBA(t)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/bc-authorize",
		strings.NewReader(url.Values{
			"login_hint": {r.user.Email},
			"scope":      {"openid"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.client.ClientID, "ciba-secret")
	rsp, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	var ar ciba.AuthorizeResponse
	_ = json.Unmarshal(body, &ar)

	id := pendingCIBAID(t, r.q, r.tenant.ID, r.user.ID)
	if err := ciba.Deny(context.Background(), r.q, r.tenant.ID, id); err != nil {
		t.Fatal(err)
	}

	time.Sleep(250 * time.Millisecond)
	preq, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type":  {ciba.GrantType},
			"auth_req_id": {ar.AuthReqID},
		}.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.SetBasicAuth(r.client.ClientID, "ciba-secret")
	prsp, _ := http.DefaultClient.Do(preq)
	pbody, _ := io.ReadAll(prsp.Body)
	prsp.Body.Close()
	if !strings.Contains(string(pbody), "access_denied") {
		t.Fatalf("expected access_denied, got %d %s", prsp.StatusCode, pbody)
	}
}
