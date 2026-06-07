//go:build integration

package authflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/net/publicsuffix"

	"github.com/hepangda/keyforge/internal/auth/password"
	"github.com/hepangda/keyforge/internal/oauth/authflow"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/jar"
	"github.com/hepangda/keyforge/internal/oauth/par"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

const issuerURL = "https://parjar.test"

// parJarRig is a small fixture: a tenant with one confidential client that
// uses private_key_jwt for token-endpoint auth (so PAR auth works) and has
// its public JWK registered inline (so JAR verification works against the
// same key pair).
type parJarRig struct {
	tenant  *tenants.Tenant
	client  *clients.Client
	user    *users.User
	priv    jwk.Key // client's private key for signing assertions/request objects
	tokenEP string
	srv     *httptest.Server
}

func setupParJar(t *testing.T) *parJarRig {
	t.Helper()
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	tenantsRepo := tenants.New(fx.Pool)
	tenant, err := tenantsRepo.Create(ctx, "parjar", "ParJar", issuerURL)
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	// Generate an EC keypair for the client; embed the public JWK in the
	// client's `jwks` column so both private_key_jwt and JAR resolve it.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatal(err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "client-1"); err != nil {
		t.Fatal(err)
	}
	pubJWK, err := jwk.PublicKeyOf(privJWK)
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		t.Fatal(err)
	}
	jwksJSON, _ := json.Marshal(set)

	clientsRepo := clients.New(fx.Pool)
	cli, err := clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "svc-parjar",
		ClientType:              clients.TypeConfidential,
		Name:                    "PAR/JAR client",
		TokenEndpointAuthMethod: string(clientauth.MethodPrivateKeyJWT),
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid", "profile"},
		RedirectURIs:            []string{"http://127.0.0.1/callback"},
		JWKS:                    jwksJSON,
	})
	if err != nil {
		t.Fatal(err)
	}

	usersRepo := users.New(fx.Pool)
	user, err := usersRepo.Create(ctxT, users.CreateInput{
		Email: "bob@parjar.test", EmailVerified: true,
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

	sessionStore := session.NewPostgresStore(fx.Pool)
	jarParser := jar.New(issuerURL)
	authflowH, err := authflow.New(authflow.Config{
		Pool:         fx.Pool,
		ClientsRepo:  clientsRepo,
		UsersRepo:    usersRepo,
		SessionStore: sessionStore,
		JARParser:    jarParser,
		TenantFor: func(*http.Request) (uuid.UUID, error) {
			return tenant.ID, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start the test server with a placeholder mux so we know srv.URL before
	// constructing the authenticator (whose audience is the absolute
	// /oauth/par URL).
	mux := http.NewServeMux()
	authflowH.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	lookup := &tenantClientLookup{repo: clientsRepo, tid: tenant.ID}
	auth := clientauth.NewAuthenticator(
		lookup,
		clientauth.NewPrivateKeyJWTMethod(srv.URL+"/oauth/par", nil),
	)
	parH, err := par.New(par.Config{
		Queries:       db.New(fx.Pool),
		Authenticator: auth,
		TenantFor: func(*http.Request) (uuid.UUID, error) {
			return tenant.ID, nil
		},
		TTL: 90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	parH.Routes(mux)

	return &parJarRig{
		tenant: tenant, client: cli, user: user, priv: privJWK,
		tokenEP: srv.URL + "/oauth/par", srv: srv,
	}
}

// tenantClientLookup injects the test tenant id into the context for every
// client lookup.
type tenantClientLookup struct {
	repo *clients.Repository
	tid  uuid.UUID
}

func (l *tenantClientLookup) GetByClientID(ctx context.Context, clientID string) (*clients.Client, error) {
	ctx = postgres.ContextWithTenant(ctx, l.tid)
	return l.repo.GetByClientID(ctx, clientID)
}

// signedAssertion mints a client-assertion JWT for the test client.
func (r *parJarRig) signedAssertion(t *testing.T, audience string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(r.client.ClientID).
		Subject(r.client.ClientID).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID(uuid.NewString()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, r.priv))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// signedRequestObject mints a JAR `request` JWT carrying authorize params.
func (r *parJarRig) signedRequestObject(t *testing.T, params map[string]any) string {
	t.Helper()
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(r.client.ClientID).
		Audience([]string{issuerURL}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID(uuid.NewString())
	for k, v := range params {
		_ = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, r.priv))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestPARHappyPath(t *testing.T) {
	r := setupParJar(t)

	verifier, _ := pkce.GenerateVerifier()
	challenge := pkce.DeriveChallenge(verifier)

	// 1) POST authorize params (plus the client_assertion for auth) to /oauth/par.
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {r.client.ClientID},
		"redirect_uri":          {"http://127.0.0.1/callback"},
		"scope":                 {"openid profile"},
		"state":                 {"par-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"client_assertion_type": {clientauth.JWTAssertionType},
		"client_assertion":      {r.signedAssertion(t, r.srv.URL+"/oauth/par")},
	}
	rsp, err := http.Post(r.srv.URL+"/oauth/par",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(rsp.Body)
		t.Fatalf("PAR status %d: %s", rsp.StatusCode, body)
	}
	var pr par.PushResponse
	_ = json.NewDecoder(rsp.Body).Decode(&pr)
	rsp.Body.Close()
	if !strings.HasPrefix(pr.RequestURI, par.URNPrefix) {
		t.Fatalf("bad request_uri %q", pr.RequestURI)
	}

	// 2) Redirect through /oauth/authorize with only client_id + request_uri.
	loc := authRoundWithJar(t, r.srv, r.client.ClientID, "http://127.0.0.1/callback",
		url.Values{"request_uri": {pr.RequestURI}})
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" {
		t.Fatalf("no code: %s", loc)
	}
	if u.Query().Get("state") != "par-state" {
		t.Errorf("state = %q, want par-state", u.Query().Get("state"))
	}

	// 3) Replay must fail (request_uri is single-use).
	loc2 := authRoundWithJar(t, r.srv, r.client.ClientID, "http://127.0.0.1/callback",
		url.Values{"request_uri": {pr.RequestURI}})
	if !strings.Contains(loc2, "PAR%20request%20invalid") && !strings.Contains(loc2, "request_uri%20already%20consumed") {
		// PAR replay rejection is rendered as the server-side error page;
		// loc2 will be empty when the response is an HTML error not a redirect.
		if loc2 != "" {
			t.Errorf("expected PAR replay rejection, got redirect %q", loc2)
		}
	}
}

func TestJARHappyPath(t *testing.T) {
	r := setupParJar(t)

	verifier, _ := pkce.GenerateVerifier()
	challenge := pkce.DeriveChallenge(verifier)

	// Sign a request object containing the authorize parameters.
	requestJWT := r.signedRequestObject(t, map[string]any{
		"response_type":         "code",
		"client_id":             r.client.ClientID,
		"redirect_uri":          "http://127.0.0.1/callback",
		"scope":                 "openid profile",
		"state":                 "jar-state",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	})

	loc := authRoundWithJar(t, r.srv, r.client.ClientID, "http://127.0.0.1/callback",
		url.Values{"request": {requestJWT}})
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" {
		t.Fatalf("no code from JAR flow: %s", loc)
	}
	if u.Query().Get("state") != "jar-state" {
		t.Errorf("state = %q, want jar-state", u.Query().Get("state"))
	}
}

// authRoundWithJar drives /authorize → login → consent and returns the final
// redirect URI (Location header on the consent POST response). extraParams
// are merged into the /authorize query string.
func authRoundWithJar(t *testing.T, srv *httptest.Server, clientID, redirectURI string, extraParams url.Values) string {
	t.Helper()
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), redirectURI) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	q := url.Values{"client_id": {clientID}}
	for k, v := range extraParams {
		q[k] = v
	}
	rsp, err := client.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	if rsp.Request.URL.Path != "/oauth/login" {
		// Likely a server-rendered error page; surface it.
		return ""
	}
	arID := rsp.Request.URL.Query().Get("ar")

	loginGet, _ := client.Get(srv.URL + "/oauth/login?ar=" + arID)
	body, _ := io.ReadAll(loginGet.Body)
	loginGet.Body.Close()
	loginCSRF := extractCSRF(t, string(body))

	rsp, _ = client.PostForm(srv.URL+"/oauth/login", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {loginCSRF},
		"email":           {"bob@parjar.test"},
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
	return rsp.Header.Get("Location")
}
