//go:build integration

package authflow_test

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

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/hepangda/keyforge/internal/auth/password"
	"github.com/hepangda/keyforge/internal/oauth/authflow"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

func TestAuthCodeFlow_HappyPath(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	// Seed: tenant, public PKCE client, user with a known password.
	tenantRepo := tenants.New(fx.Pool)
	tenant, err := tenantRepo.Create(ctx, "ac-test", "AC Test", "https://ac.test")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	clientRepo := clients.New(fx.Pool)
	cli, err := clientRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "spa",
		ClientType:              clients.TypePublic,
		Name:                    "Demo SPA",
		TokenEndpointAuthMethod: string(clientauth.MethodNone),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		Scopes:                  []string{"openid", "profile", "email"},
		RedirectURIs:            []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	userRepo := users.New(fx.Pool)
	user, err := userRepo.Create(ctxT, users.CreateInput{
		Email:         "alice@ac.test",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := password.Hash("hunter22", password.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := userRepo.UpsertCredential(ctxT, users.Credential{
		UserID: user.ID, PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}

	// Wire the authflow handler bound to this tenant.
	sessionStore := session.NewPostgresStore(fx.Pool)
	handler, err := authflow.New(authflow.Config{
		Pool:         fx.Pool,
		ClientsRepo:  clientRepo,
		UsersRepo:    userRepo,
		SessionStore: sessionStore,
		TenantFor: func(*http.Request) (uuid.UUID, error) {
			return tenant.ID, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	handler.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Cookie jar so the session and CSRF cookies follow us through redirects.
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop at the client's redirect_uri so we can read the code/state.
			if strings.HasPrefix(req.URL.String(), "http://127.0.0.1/callback") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	verifier, err := pkce.GenerateVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := pkce.DeriveChallenge(verifier)
	state := "xyz-state"

	authURL := srv.URL + "/oauth/authorize?" + url.Values{
		"client_id":             {cli.ClientID},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"redirect_uri":          {"http://127.0.0.1/callback"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// 1) GET /oauth/authorize → 302 /oauth/login?ar=...
	rsp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	if rsp.Request.URL.Path != "/oauth/login" {
		t.Fatalf("after authorize: path = %s", rsp.Request.URL.Path)
	}
	arID := rsp.Request.URL.Query().Get("ar")
	if arID == "" {
		t.Fatal("missing ar in login URL")
	}

	// Pull the CSRF token out of the rendered login form so we can include
	// it in the POST. The form is small enough to scan with strings.Contains.
	loginGet, err := client.Get(srv.URL + "/oauth/login?ar=" + arID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(loginGet.Body)
	loginGet.Body.Close()
	csrfTok := extractCSRF(t, string(body))

	// 2) POST /oauth/login with good credentials → 302 /oauth/consent?ar=...
	form := url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {csrfTok},
		"email":           {"alice@ac.test"},
		"password":        {"hunter22"},
	}
	rsp, err = client.PostForm(srv.URL+"/oauth/login", form)
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	if rsp.Request.URL.Path != "/oauth/consent" {
		t.Fatalf("after login: path = %s", rsp.Request.URL.Path)
	}

	// Pull consent CSRF token.
	consentGet, err := client.Get(srv.URL + "/oauth/consent?ar=" + arID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(consentGet.Body)
	consentGet.Body.Close()
	consentCSRF := extractCSRF(t, string(body))

	// 3) POST /oauth/consent decision=allow → 302 to redirect_uri with code+state.
	rsp, err = client.PostForm(srv.URL+"/oauth/consent", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {consentCSRF},
		"decision":        {"allow"},
	})
	if err != nil {
		t.Fatalf("consent post: %v", err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()

	loc := rsp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("no Location after consent, status %d", rsp.StatusCode)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "127.0.0.1" || u.Path != "/callback" {
		t.Errorf("unexpected redirect %s", loc)
	}
	if got := u.Query().Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
	if u.Query().Get("code") == "" {
		t.Error("missing code in redirect")
	}

	// keep imports we touched
	_ = json.Marshal
}

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("csrf token not found in body:\n%s", body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("malformed csrf hidden input")
	}
	return rest[:end]
}
