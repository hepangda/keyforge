//go:build integration

package tokenapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
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
	"github.com/hepangda/keyforge/internal/oauth/mtls"
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

// mintCert produces a fresh self-signed cert for tests.
func mintCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// switchableExtractor is an mtls.CertExtractor whose returned cert can be
// flipped per-test by setting Current.
type switchableExtractor struct {
	Current *x509.Certificate
}

func (s *switchableExtractor) Extract(_ *http.Request) (*x509.Certificate, error) {
	if s.Current == nil {
		return nil, mtls.ErrNoClientCert
	}
	return s.Current, nil
}

// setupMTLS builds a full rig with a switchable mTLS extractor and a
// confidential client registered to use client_secret_basic auth (so the
// /token call doesn't need a TLS handshake itself — the extractor is
// independent of how the client authenticated).
func setupMTLS(t *testing.T) (*rig, *switchableExtractor) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	tenantsRepo := tenants.New(fx.Pool)
	tenant, err := tenantsRepo.Create(ctx, "mtls", "MTLS", "https://mtls.test")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	clientsRepo := clients.New(fx.Pool)
	hash, _ := clientauth.HashSecret("svc-secret")
	cli, err := clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                              "mtls-spa",
		ClientType:                            clients.TypeConfidential,
		Name:                                  "mTLS-bound client",
		ClientSecretHash:                      hash,
		TokenEndpointAuthMethod:               string(clientauth.MethodSecretBasic),
		GrantTypes:                            []string{"authorization_code", "refresh_token"},
		Scopes:                                []string{"openid", "profile"},
		RedirectURIs:                          []string{"http://127.0.0.1/callback"},
		TLSClientCertificateBoundAccessTokens: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	usersRepo := users.New(fx.Pool)
	user, err := usersRepo.Create(ctxT, users.CreateInput{
		Email: "u@mtls.test", EmailVerified: true,
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

	sessionStore := session.NewPostgresStore(fx.Pool)
	authflowH, err := authflow.New(authflow.Config{
		Pool: fx.Pool, ClientsRepo: clientsRepo, UsersRepo: usersRepo,
		SessionStore: sessionStore, TenantFor: tenantFor,
	})
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := tokens.NewIssuer(tokens.Config{
		Pool: fx.Pool, Signer: signer, UsersRepo: usersRepo,
		Issuer: "https://mtls.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := clientauth.NewAuthenticator(
		&clientLookup{repo: clientsRepo, tid: tenant.ID, pool: fx.Pool},
		clientauth.NewSecretBasicMethod(),
		clientauth.NewSecretPostMethod(),
		clientauth.NewNoneMethod(),
	)

	extractor := &switchableExtractor{}

	tokenH, err := tokenapi.New(tokenapi.Config{
		Queries:       db.New(fx.Pool),
		Issuer:        issuer,
		Authenticator: auth,
		ClientsRepo:   clientsRepo,
		UsersRepo:     usersRepo,
		MTLSExtractor: extractor,
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

	r := &rig{
		tenant: tenant, client: cli, user: user, clientPK: cli.ID,
		srv: srv, queries: db.New(fx.Pool), issuer: issuer,
		clientsRepo: clientsRepo, usersRepo: usersRepo,
		tenantsRepo: tenantsRepo, sessionStore: sessionStore,
	}
	return r, extractor
}

// authCodeRoundMTLS mirrors authCodeRound but for the mTLS test's user.
func authCodeRoundMTLS(t *testing.T, srv *httptest.Server, clientID, redirectURI, scopes, state, challenge, email, password string) string {
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
	loginGet, _ := client.Get(srv.URL + "/oauth/login?ar=" + arID)
	body, _ := io.ReadAll(loginGet.Body)
	loginGet.Body.Close()
	loginCSRF := extractTokenFromMTLSBody(t, string(body))
	rsp, _ = client.PostForm(srv.URL+"/oauth/login", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {loginCSRF},
		"email":           {email},
		"password":        {password},
	})
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	consentGet, _ := client.Get(srv.URL + "/oauth/consent?ar=" + arID)
	body, _ = io.ReadAll(consentGet.Body)
	consentGet.Body.Close()
	consentCSRF := extractTokenFromMTLSBody(t, string(body))
	rsp, _ = client.PostForm(srv.URL+"/oauth/consent", url.Values{
		"auth_request_id": {arID},
		"csrf_token":      {consentCSRF},
		"decision":        {"allow"},
	})
	_, _ = io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()
	loc := rsp.Header.Get("Location")
	u, _ := url.Parse(loc)
	return u.Query().Get("code")
}

func extractTokenFromMTLSBody(t *testing.T, body string) string {
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

func TestMTLSBoundAccessTokensAndUserInfo(t *testing.T) {
	r, extractor := setupMTLS(t)

	cert := mintCert(t, "issuance-time")

	verifier, _ := pkce.GenerateVerifier()
	challenge := pkce.DeriveChallenge(verifier)
	code := authCodeRoundMTLS(
		t, r.srv,
		r.client.ClientID, "http://127.0.0.1/callback",
		"openid profile", "s", challenge,
		"u@mtls.test", "hunter22",
	)
	if code == "" {
		t.Fatal("no code")
	}

	// Token endpoint: present the client cert via the extractor.
	extractor.Current = cert
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://127.0.0.1/callback"},
			"client_id":     {r.client.ClientID},
			"code_verifier": {verifier},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.client.ClientID, "svc-secret")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d body %s", rsp.StatusCode, body)
	}
	var tr tokens.Response
	_ = json.Unmarshal(body, &tr)
	if tr.AccessToken == "" {
		t.Fatal("missing access_token")
	}

	// Introspect must surface cnf.x5t#S256.
	introReq, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/introspect",
		strings.NewReader(url.Values{"token": {tr.AccessToken}}.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(r.client.ClientID, "svc-secret")
	introRsp, _ := http.DefaultClient.Do(introReq)
	var intro map[string]any
	_ = json.NewDecoder(introRsp.Body).Decode(&intro)
	introRsp.Body.Close()
	cnf, _ := intro["cnf"].(map[string]any)
	if cnf["x5t#S256"] != mtls.Thumbprint(cert) {
		t.Errorf("introspect missing x5t#S256: %+v", intro)
	}

	// /userinfo with the SAME cert succeeds.
	extractor.Current = cert
	ui1 := getUserInfoMTLS(t, r.srv.URL, tr.AccessToken)
	if ui1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(ui1.Body)
		t.Fatalf("userinfo with matching cert: status %d body %s", ui1.StatusCode, body)
	}
	ui1.Body.Close()

	// /userinfo with NO cert fails.
	extractor.Current = nil
	ui2 := getUserInfoMTLS(t, r.srv.URL, tr.AccessToken)
	if ui2.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo without cert: status %d, want 401", ui2.StatusCode)
	}
	ui2.Body.Close()

	// /userinfo with a DIFFERENT cert fails.
	extractor.Current = mintCert(t, "wrong-cert")
	ui3 := getUserInfoMTLS(t, r.srv.URL, tr.AccessToken)
	if ui3.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo with wrong cert: status %d, want 401", ui3.StatusCode)
	}
	ui3.Body.Close()
}

func getUserInfoMTLS(t *testing.T, base, accessToken string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodGet, base+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return rsp
}

// silence unused imports if Go's vet warnings about tls become noise.
var _ = tls.Config{}
