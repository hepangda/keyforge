//go:build integration

package tokenapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/hepangda/keyforge/internal/auth/password"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/oauth/authflow"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/dpop"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/oauth/tokenapi"
	"github.com/hepangda/keyforge/internal/oauth/tokens"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

// envelope returns a deterministic envelope for jwks signing in tests.
func envelope(t *testing.T) *kcrypto.Envelope {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	env, err := kcrypto.NewEnvelope(kek)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

type rig struct {
	tenant       *tenants.Tenant
	client       *clients.Client
	user         *users.User
	clientPK     uuid.UUID
	srv          *httptest.Server
	queries      *db.Queries
	issuer       *tokens.Issuer
	clientsRepo  *clients.Repository
	usersRepo    *users.Repository
	tenantsRepo  *tenants.Repository
	sessionStore session.Store
}

func setup(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	tenantsRepo := tenants.New(fx.Pool)
	tenant, err := tenantsRepo.Create(ctx, "tok", "Tok", "https://tok.test")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	clientsRepo := clients.New(fx.Pool)
	cli, err := clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "spa",
		ClientType:              clients.TypePublic,
		Name:                    "Demo SPA",
		TokenEndpointAuthMethod: string(clientauth.MethodNone),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		RedirectURIs:            []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	usersRepo := users.New(fx.Pool)
	user, err := usersRepo.Create(ctxT, users.CreateInput{
		Email: "alice@tok.test", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := password.Hash("hunter22", password.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := usersRepo.UpsertCredential(ctxT, users.Credential{
		UserID: user.ID, PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}

	// Ensure a JWKS signing key exists for the tenant scope (uses the
	// global keyset since we never pass a non-Nil tenant id).
	store := jwks.NewPostgresStore(fx.Pool, envelope(t), jwks.SystemClock())
	if _, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig); err != nil {
		t.Fatal(err)
	}
	signer := jwks.NewSigner(store)

	tenantFor := func(*http.Request) (uuid.UUID, error) { return tenant.ID, nil }

	sessionStore := session.NewPostgresStore(fx.Pool)
	authflowH, err := authflow.New(authflow.Config{
		Pool:         fx.Pool,
		ClientsRepo:  clientsRepo,
		UsersRepo:    usersRepo,
		SessionStore: sessionStore,
		TenantFor:    tenantFor,
	})
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := tokens.NewIssuer(tokens.Config{
		Pool: fx.Pool, Signer: signer, UsersRepo: usersRepo,
		Issuer: "https://tok.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := clientauth.NewAuthenticator(
		&clientLookup{repo: clientsRepo, tid: tenant.ID, pool: fx.Pool},
		clientauth.NewSecretBasicMethod(),
		clientauth.NewSecretPostMethod(),
		clientauth.NewPrivateKeyJWTMethod("https://tok.test/oauth/token", nil),
		clientauth.NewNoneMethod(),
	)

	tokenH, err := tokenapi.New(tokenapi.Config{
		Queries:       db.New(fx.Pool),
		Issuer:        issuer,
		Authenticator: auth,
		ClientsRepo:   clientsRepo,
		UsersRepo:     usersRepo,
		DPoPValidator: dpop.New(60*time.Second, dpop.NewMemoryReplay()),
		TenantFor:     tenantFor,
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	authflowH.Routes(mux)
	tokenH.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &rig{
		tenant: tenant, client: cli, user: user, clientPK: cli.ID,
		srv: srv, queries: db.New(fx.Pool), issuer: issuer,
		clientsRepo: clientsRepo, usersRepo: usersRepo,
		tenantsRepo: tenantsRepo, sessionStore: sessionStore,
	}
}

// clientLookup adapts our clients.Repository to the ClientLookup interface
// by injecting the tenant id into the context for every lookup.
type clientLookup struct {
	repo *clients.Repository
	tid  uuid.UUID
	pool any
}

func (c *clientLookup) GetByClientID(ctx context.Context, clientID string) (*clients.Client, error) {
	ctx = postgres.ContextWithTenant(ctx, c.tid)
	return c.repo.GetByClientID(ctx, clientID)
}

// authCodeRound runs through /oauth/authorize → /oauth/login → /oauth/consent
// and returns the issued authorization code.
func authCodeRound(t *testing.T, srv *httptest.Server, clientID, redirectURI, scopes, state, challenge string) string {
	t.Helper()
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), redirectURI) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	authURL := srv.URL + "/oauth/authorize?" + url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"scope":                 {scopes},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	rsp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	arID := rsp.Request.URL.Query().Get("ar")
	if arID == "" {
		t.Fatal("no ar in login URL")
	}

	loginGet, _ := client.Get(srv.URL + "/oauth/login?ar=" + arID)
	body, _ := io.ReadAll(loginGet.Body)
	loginGet.Body.Close()
	loginCSRF := extractToken(t, string(body))

	rsp, err = client.PostForm(srv.URL+"/oauth/login", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {loginCSRF},
		"email":           {"alice@tok.test"},
		"password":        {"hunter22"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()

	consentGet, _ := client.Get(srv.URL + "/oauth/consent?ar=" + arID)
	body, _ = io.ReadAll(consentGet.Body)
	consentGet.Body.Close()
	consentCSRF := extractToken(t, string(body))

	rsp, err = client.PostForm(srv.URL+"/oauth/consent", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {consentCSRF},
		"decision":        {"allow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	loc := rsp.Header.Get("Location")
	u, _ := url.Parse(loc)
	return u.Query().Get("code")
}

func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("csrf not found in:\n%s", body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	return rest[:end]
}

func TestFullAuthCodeAndRefreshFlow(t *testing.T) {
	r := setup(t)

	verifier, _ := pkce.GenerateVerifier()
	challenge := pkce.DeriveChallenge(verifier)
	code := authCodeRound(
		t, r.srv,
		r.client.ClientID, "http://127.0.0.1/callback",
		"openid profile email offline_access",
		"abc", challenge,
	)
	if code == "" {
		t.Fatal("no authorization code")
	}

	// 1) Exchange code for tokens
	tokRsp, err := http.PostForm(r.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1/callback"},
		"client_id":     {r.client.ClientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokRsp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokRsp.Body)
		t.Fatalf("token status %d: %s", tokRsp.StatusCode, body)
	}
	var tr tokens.Response
	_ = json.NewDecoder(tokRsp.Body).Decode(&tr)
	tokRsp.Body.Close()
	if tr.AccessToken == "" || tr.RefreshToken == "" || tr.IDToken == "" {
		t.Fatalf("missing tokens in response: %+v", tr)
	}

	// 2) Re-exchanging the same code must fail
	again, _ := http.PostForm(r.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1/callback"},
		"client_id":     {r.client.ClientID},
		"code_verifier": {verifier},
	})
	if again.StatusCode == http.StatusOK {
		t.Errorf("code replay should fail")
	}
	again.Body.Close()

	// 3) UserInfo
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodGet, r.srv.URL+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rsp.Body)
		t.Fatalf("userinfo status %d: %s", rsp.StatusCode, body)
	}
	var ui map[string]any
	_ = json.NewDecoder(rsp.Body).Decode(&ui)
	rsp.Body.Close()
	if ui["sub"] != r.user.ID.String() {
		t.Errorf("userinfo sub = %v, want %v", ui["sub"], r.user.ID)
	}
	if ui["email"] != "alice@tok.test" {
		t.Errorf("userinfo email = %v", ui["email"])
	}

	// 4) Introspect AT
	introRsp, _ := http.PostForm(r.srv.URL+"/oauth/introspect", url.Values{
		"token":     {tr.AccessToken},
		"client_id": {r.client.ClientID},
	})
	var intro map[string]any
	_ = json.NewDecoder(introRsp.Body).Decode(&intro)
	introRsp.Body.Close()
	if intro["active"] != true {
		t.Fatalf("introspect should report active: %+v", intro)
	}

	// 5) Refresh
	refRsp, err := http.PostForm(r.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tr.RefreshToken},
		"client_id":     {r.client.ClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if refRsp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refRsp.Body)
		t.Fatalf("refresh status %d: %s", refRsp.StatusCode, body)
	}
	var tr2 tokens.Response
	_ = json.NewDecoder(refRsp.Body).Decode(&tr2)
	refRsp.Body.Close()
	if tr2.AccessToken == tr.AccessToken {
		t.Error("refresh should mint a NEW access token")
	}
	if tr2.RefreshToken == tr.RefreshToken {
		t.Error("refresh should rotate the refresh token")
	}

	// 6) Refresh reuse detection: reusing the OLD refresh token must fail
	// AND must revoke the new one too.
	bad, _ := http.PostForm(r.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tr.RefreshToken}, // the original
		"client_id":     {r.client.ClientID},
	})
	if bad.StatusCode == http.StatusOK {
		t.Error("reusing consumed refresh token should fail")
	}
	bad.Body.Close()

	// Now the newly issued RT must also be revoked.
	bad2, _ := http.PostForm(r.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tr2.RefreshToken},
		"client_id":     {r.client.ClientID},
	})
	if bad2.StatusCode == http.StatusOK {
		t.Error("after reuse detection, the rotated RT should also be revoked")
	}
	bad2.Body.Close()

	// 7) Revoke the original AT and confirm introspect reports inactive.
	revRsp, _ := http.PostForm(r.srv.URL+"/oauth/revoke", url.Values{
		"token":     {tr.AccessToken},
		"client_id": {r.client.ClientID},
	})
	revRsp.Body.Close()
	introRsp2, _ := http.PostForm(r.srv.URL+"/oauth/introspect", url.Values{
		"token":     {tr.AccessToken},
		"client_id": {r.client.ClientID},
	})
	var intro2 map[string]any
	_ = json.NewDecoder(introRsp2.Body).Decode(&intro2)
	introRsp2.Body.Close()
	if intro2["active"] != false {
		t.Errorf("revoked AT should introspect as inactive: %+v", intro2)
	}
}
