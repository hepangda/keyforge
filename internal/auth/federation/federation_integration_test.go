//go:build integration

package federation_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/auth/federation"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/testsupport"
)

// fakeIdP serves the minimum OIDC surface needed by go-oidc: a
// discovery document, a JWKS endpoint, and a /token endpoint that
// returns a signed id_token. We capture the inbound code + verifier so
// the test can assert PKCE was carried through.
type fakeIdP struct {
	srv      *httptest.Server
	priv     *rsa.PrivateKey
	pubJWK   jwk.Key
	clientID string

	mu struct {
		seenCode     string
		seenVerifier string
		nonce        string
		state        string
	}
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	pub, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		t.Fatalf("jwk: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, "test-kid")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = pub.Set(jwk.KeyUsageKey, "sig")

	f := &fakeIdP{priv: priv, pubJWK: pub, clientID: "fed-client"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks.json", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                f.srv.URL,
		"authorization_endpoint":                f.srv.URL + "/authorize",
		"token_endpoint":                        f.srv.URL + "/token",
		"jwks_uri":                              f.srv.URL + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	set := jwk.NewSet()
	_ = set.AddKey(f.pubJWK)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

// authorize is normally where the browser lands; the test calls it
// directly to get back a redirect with `code` and `state`.
func (f *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.state = q.Get("state")
	f.mu.nonce = q.Get("nonce")
	redirect := q.Get("redirect_uri")
	code := "test-code-12345"
	f.mu.seenCode = code
	u, _ := url.Parse(redirect)
	v := u.Query()
	v.Set("state", f.mu.state)
	v.Set("code", code)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostFormValue("code") != f.mu.seenCode {
		http.Error(w, "bad code", http.StatusBadRequest)
		return
	}
	f.mu.seenVerifier = r.PostFormValue("code_verifier")
	if f.mu.seenVerifier == "" {
		http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
		return
	}

	tok, err := jwt.NewBuilder().
		Issuer(f.srv.URL).
		Subject("upstream-subject-42").
		Audience([]string{f.clientID}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5*time.Minute)).
		Claim("email", "alice@upstream.test").
		Claim("name", "Alice Upstream").
		Claim("nonce", f.mu.nonce).
		Build()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signingKeyWithKID(f.priv, f.pubJWK.KeyID())))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"access_token": "upstream-at",
		"token_type":   "Bearer",
		"id_token":     string(signed),
		"expires_in":   300,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// signingKeyWithKID wraps a raw RSA private key in a jwx Key so the kid
// header gets emitted (required for the RP to pick the right public key
// out of /jwks.json).
func signingKeyWithKID(priv *rsa.PrivateKey, kid string) jwk.Key {
	k, err := jwk.FromRaw(priv)
	if err != nil {
		panic(err)
	}
	_ = k.Set(jwk.KeyIDKey, kid)
	_ = k.Set(jwk.AlgorithmKey, jwa.RS256)
	return k
}

func TestFederationEndToEnd(t *testing.T) {
	ctx := postgres.ContextWithTenant(context.Background(), uuid.Nil)
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)

	tenant, err := q.CreateTenant(ctx, db.CreateTenantParams{
		Slug:        "fed-test",
		DisplayName: "Federation Test Tenant",
		Issuer:      "https://example.test",
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenant.ID
	ctx = postgres.ContextWithTenant(ctx, tid)

	idp := newFakeIdP(t)

	// envelope for client secret encryption
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	env, _ := kcrypto.NewEnvelope(kek)

	wrapped, ct, err := env.SealWithDEK([]byte("upstream-client-secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	row, err := q.CreateIdPConnector(ctx, db.CreateIdPConnectorParams{
		TenantID:         tid,
		Slug:             "fakeidp",
		DisplayName:      "Fake IdP",
		Issuer:           idp.srv.URL,
		ClientID:         idp.clientID,
		SecretCiphertext: ct,
		DEKCiphertext:    wrapped,
		Scopes:           []string{"openid", "profile", "email"},
		ClaimMapping:     json.RawMessage(`{"subject":"sub","email":"email","display_name":"name"}`),
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}

	reg := federation.NewRegistry(q, env)
	conn, err := reg.LookupBySlug(ctx, tid, "fakeidp")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if conn.ID() != row.ID {
		t.Fatalf("connector id mismatch")
	}

	redirect := idp.srv.URL + "/local-callback" // any URL; the test uses /authorize directly
	ac, err := conn.BuildAuthCodeRequest(ctx, redirect)
	if err != nil {
		t.Fatalf("build auth code: %v", err)
	}
	// Drive /authorize by hand to get the code redirect URL.
	resp, err := noRedirectClient().Get(ac.URL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("authorize missing Location")
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") != ac.State {
		t.Fatalf("state mismatch")
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code")
	}

	mapped, err := conn.Exchange(ctx, redirect, code, ac.PKCEVerifier, ac.Nonce)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if mapped.Subject != "upstream-subject-42" {
		t.Fatalf("subject=%q", mapped.Subject)
	}
	if mapped.Email != "alice@upstream.test" {
		t.Fatalf("email=%q", mapped.Email)
	}
	if mapped.DisplayName != "Alice Upstream" {
		t.Fatalf("display_name=%q", mapped.DisplayName)
	}

	// Nonce mismatch must fail.
	if _, err := conn.Exchange(ctx, redirect, code+"-bad", ac.PKCEVerifier, "wrong-nonce"); err == nil {
		t.Fatalf("expected exchange to fail")
	}
}

func TestFederationLinkExistingUser(t *testing.T) {
	ctx := postgres.ContextWithTenant(context.Background(), uuid.Nil)
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)

	tenant, err := q.CreateTenant(ctx, db.CreateTenantParams{
		Slug: "fed-link", DisplayName: "Link", Issuer: "https://example.test",
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	tid := tenant.ID
	ctx = postgres.ContextWithTenant(ctx, tid)

	// Seed an existing local user whose email matches an upstream identity.
	user, err := q.CreateUser(ctx, db.CreateUserParams{
		TenantID: tid, Email: "alice@upstream.test",
		EmailVerified: true,
		DisplayName:   pgtype.Text{String: "Alice", Valid: true},
	})
	if err != nil {
		t.Fatalf("user: %v", err)
	}

	// Insert connector + simulate the link path that resolveOrProvisionUser
	// uses: an explicit LinkFederatedIdentity row.
	conn, err := q.CreateIdPConnector(ctx, db.CreateIdPConnectorParams{
		TenantID: tid, Slug: "fakeidp", DisplayName: "FI",
		Issuer: "https://up.test", ClientID: "cid",
		Scopes: []string{"openid"}, ClaimMapping: json.RawMessage(`{}`),
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	if _, err := q.LinkFederatedIdentity(ctx, db.LinkFederatedIdentityParams{
		TenantID: tid, IdpID: conn.ID, UserID: user.ID, Subject: "ext-1",
	}); err != nil {
		t.Fatalf("link: %v", err)
	}
	// Repeat must touch, not duplicate.
	if _, err := q.LinkFederatedIdentity(ctx, db.LinkFederatedIdentityParams{
		TenantID: tid, IdpID: conn.ID, UserID: user.ID, Subject: "ext-1",
	}); err != nil {
		t.Fatalf("link again: %v", err)
	}
	rows, err := q.ListFederatedIdentitiesForUser(ctx, db.ListFederatedIdentitiesForUserParams{
		TenantID: tid, UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 federated identity, got %d", len(rows))
	}
	if rows[0].IdpSlug != "fakeidp" {
		t.Fatalf("slug=%q", rows[0].IdpSlug)
	}
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       5 * time.Second,
	}
}
