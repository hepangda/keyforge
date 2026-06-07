//go:build integration

package authflow_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/net/publicsuffix"

	"github.com/hepangda/keyforge/internal/auth/password"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/oauth/authflow"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/jarm"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

func TestJARMQueryJWTHappyPath(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	// Seed a tenant + public PKCE client + user.
	tenantsRepo := tenants.New(fx.Pool)
	tenant, err := tenantsRepo.Create(ctx, "jarm", "JARM", "https://jarm.test")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	clientsRepo := clients.New(fx.Pool)
	cli, err := clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "jarm-spa",
		ClientType:              clients.TypePublic,
		Name:                    "JARM SPA",
		TokenEndpointAuthMethod: string(clientauth.MethodNone),
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid", "profile"},
		RedirectURIs:            []string{"http://127.0.0.1/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	usersRepo := users.New(fx.Pool)
	user, err := usersRepo.Create(ctxT, users.CreateInput{
		Email: "jarm@jarm.test", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := password.Hash("hunter22", password.DefaultParams())
	if err := usersRepo.UpsertCredential(ctxT, users.Credential{
		UserID: user.ID, PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}

	// Ensure a global signing key + Signer for JARM.
	env, err := kcrypto.NewEnvelope(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := jwks.NewPostgresStore(fx.Pool, env, jwks.SystemClock())
	if _, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig); err != nil {
		t.Fatal(err)
	}
	signer := jwks.NewSigner(store)
	responder, err := jarm.New(jarm.Config{Signer: signer, Issuer: "https://jarm.test"})
	if err != nil {
		t.Fatal(err)
	}

	sessionStore := session.NewPostgresStore(fx.Pool)
	h, err := authflow.New(authflow.Config{
		Pool:          fx.Pool,
		ClientsRepo:   clientsRepo,
		UsersRepo:     usersRepo,
		SessionStore:  sessionStore,
		JARMResponder: responder,
		TenantFor:     func(*http.Request) (uuid.UUID, error) { return tenant.ID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	h.Routes(mux)
	srv := newTestServer(t, mux)

	verifier, _ := pkce.GenerateVerifier()
	challenge := pkce.DeriveChallenge(verifier)
	state := "jarm-state"

	jarjar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{
		Jar: jarjar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), "http://127.0.0.1/callback") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	q := url.Values{
		"client_id":             {cli.ClientID},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"redirect_uri":          {"http://127.0.0.1/callback"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"response_mode":         {"query.jwt"},
	}
	rsp, err := client.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	arID := rsp.Request.URL.Query().Get("ar")

	loginGet, _ := client.Get(srv.URL + "/oauth/login?ar=" + arID)
	body, _ := io.ReadAll(loginGet.Body)
	loginGet.Body.Close()
	loginCSRF := extractCSRF(t, string(body))
	rsp, _ = client.PostForm(srv.URL+"/oauth/login", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {loginCSRF},
		"email":           {"jarm@jarm.test"},
		"password":        {"hunter22"},
	})
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()

	consentGet, _ := client.Get(srv.URL + "/oauth/consent?ar=" + arID)
	body, _ = io.ReadAll(consentGet.Body)
	consentGet.Body.Close()
	consentCSRF := extractCSRF(t, string(body))
	rsp, _ = client.PostForm(srv.URL+"/oauth/consent", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {consentCSRF},
		"decision":        {"allow"},
	})
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
	// JARM puts everything in ?response=<jwt> — no code/state at top level.
	if u.Query().Get("code") != "" {
		t.Errorf("unexpected top-level code in JARM redirect: %s", loc)
	}
	if u.Query().Get("state") != "" {
		t.Errorf("unexpected top-level state in JARM redirect: %s", loc)
	}
	responseJWT := u.Query().Get("response")
	if responseJWT == "" {
		t.Fatalf("no response JWT in redirect: %s", loc)
	}

	// Verify the JARM response JWT against the JWKS public set.
	set, err := store.PublicSet(ctx, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(
		[]byte(responseJWT),
		jwt.WithKeySet(set),
		jwt.WithIssuer("https://jarm.test"),
		jwt.WithAudience(cli.ClientID),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("verify JARM jwt: %v", err)
	}
	gotCode, _ := tok.Get("code")
	gotState, _ := tok.Get("state")
	if gotCode == "" {
		t.Errorf("JARM jwt missing code")
	}
	if gotState != state {
		t.Errorf("JARM state = %v, want %s", gotState, state)
	}
}

// newTestServer wraps httptest.NewServer with a Cleanup so the caller
// doesn't repeat it in every test.
func newTestServer(t *testing.T, mux http.Handler) *testServer {
	t.Helper()
	srv := startServer(t, mux)
	return srv
}
