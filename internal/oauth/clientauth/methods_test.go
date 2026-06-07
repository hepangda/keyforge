package clientauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/storage/clients"
)

// fakeLookup is an in-memory ClientLookup.
type fakeLookup struct {
	byClientID map[string]*clients.Client
}

func (f *fakeLookup) GetByClientID(_ context.Context, clientID string) (*clients.Client, error) {
	c, ok := f.byClientID[clientID]
	if !ok {
		return nil, clients.ErrNotFound
	}
	return c, nil
}

// inMemJTI implements clientauth.JTIStore via a process-local map.
type inMemJTI struct {
	seen map[string]struct{}
}

func (s *inMemJTI) SeenJTI(_ context.Context, jti string, _ time.Duration) (bool, error) {
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	if _, ok := s.seen[jti]; ok {
		return true, nil
	}
	s.seen[jti] = struct{}{}
	return false, nil
}

func mkForm(values url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestNoneMethod(t *testing.T) {
	t.Parallel()

	cli := &clients.Client{
		ID:                      uuid.New(),
		TenantID:                uuid.New(),
		ClientID:                "spa-1",
		ClientType:              clients.TypePublic,
		TokenEndpointAuthMethod: string(clientauth.MethodNone),
	}
	lookup := &fakeLookup{byClientID: map[string]*clients.Client{cli.ClientID: cli}}
	m := clientauth.NewNoneMethod()

	// happy path
	r := mkForm(url.Values{"client_id": {"spa-1"}})
	res, err := m.Authenticate(context.Background(), r, lookup)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.Method != clientauth.MethodNone || res.Client.ID != cli.ID {
		t.Errorf("unexpected result: %+v", res)
	}

	// missing client_id => unknown
	if _, err := m.Authenticate(context.Background(), mkForm(url.Values{}), lookup); err == nil {
		t.Errorf("expected unknown client on empty form")
	}

	// confidential client cannot use `none`
	cli2 := *cli
	cli2.ClientType = clients.TypeConfidential
	lookup2 := &fakeLookup{byClientID: map[string]*clients.Client{cli2.ClientID: &cli2}}
	if _, err := m.Authenticate(context.Background(), r, lookup2); err == nil {
		t.Errorf("expected method mismatch on confidential client")
	}
}

func TestSecretBasicMethod(t *testing.T) {
	t.Parallel()

	const plain = "topsecret"
	hash, err := clientauth.HashSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	cli := &clients.Client{
		ID:                      uuid.New(),
		TenantID:                uuid.New(),
		ClientID:                "cli-basic",
		ClientType:              clients.TypeConfidential,
		ClientSecretHash:        hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
	}
	lookup := &fakeLookup{byClientID: map[string]*clients.Client{cli.ClientID: cli}}
	m := clientauth.NewSecretBasicMethod()

	// good auth
	r := mkForm(nil)
	r.SetBasicAuth(cli.ClientID, plain)
	res, err := m.Authenticate(context.Background(), r, lookup)
	if err != nil {
		t.Fatalf("good basic auth failed: %v", err)
	}
	if res.Client.ID != cli.ID {
		t.Errorf("wrong client returned")
	}

	// wrong secret
	r2 := mkForm(nil)
	r2.SetBasicAuth(cli.ClientID, "wrong")
	if _, err := m.Authenticate(context.Background(), r2, lookup); err == nil {
		t.Errorf("expected error on wrong secret")
	}

	// no basic auth => unknown
	if _, err := m.Authenticate(context.Background(), mkForm(nil), lookup); err == nil {
		t.Errorf("expected unknown without basic header")
	}
}

func TestSecretPostMethod(t *testing.T) {
	t.Parallel()
	const plain = "post-secret"
	hash, _ := clientauth.HashSecret(plain)
	cli := &clients.Client{
		ID: uuid.New(), TenantID: uuid.New(), ClientID: "cli-post",
		ClientType: clients.TypeConfidential, ClientSecretHash: hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretPost),
	}
	lookup := &fakeLookup{byClientID: map[string]*clients.Client{cli.ClientID: cli}}
	m := clientauth.NewSecretPostMethod()

	r := mkForm(url.Values{"client_id": {cli.ClientID}, "client_secret": {plain}})
	if _, err := m.Authenticate(context.Background(), r, lookup); err != nil {
		t.Fatalf("good post: %v", err)
	}

	r2 := mkForm(url.Values{"client_id": {cli.ClientID}, "client_secret": {"wrong"}})
	if _, err := m.Authenticate(context.Background(), r2, lookup); err == nil {
		t.Fatal("expected invalid client on wrong secret")
	}
}

func TestPrivateKeyJWTMethod(t *testing.T) {
	t.Parallel()

	// Client side: generate an EC keypair, register the public JWK on the
	// client record.
	priv, err := jwk.FromRaw(genECKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatal(err)
	}
	if err := priv.Set(jwk.KeyIDKey, "client-kid-1"); err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatal(err)
	}
	jwksJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	cli := &clients.Client{
		ID: uuid.New(), TenantID: uuid.New(), ClientID: "cli-jwt",
		ClientType:              clients.TypeConfidential,
		TokenEndpointAuthMethod: string(clientauth.MethodPrivateKeyJWT),
		JWKS:                    jwksJSON,
	}
	lookup := &fakeLookup{byClientID: map[string]*clients.Client{cli.ClientID: cli}}

	tokenEP := "https://keyforge.test/oauth/token"
	m := clientauth.NewPrivateKeyJWTMethod(tokenEP, &inMemJTI{})

	// good assertion
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(cli.ClientID).
		Subject(cli.ClientID).
		Audience([]string{tokenEP}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID("jti-1").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, priv))
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"client_assertion_type": {clientauth.JWTAssertionType},
		"client_assertion":      {string(signed)},
	}
	r := mkForm(form)
	res, err := m.Authenticate(context.Background(), r, lookup)
	if err != nil {
		t.Fatalf("good private_key_jwt failed: %v", err)
	}
	if res.Client.ID != cli.ID {
		t.Errorf("wrong client")
	}

	// replay must be rejected
	if _, err := m.Authenticate(context.Background(), mkForm(form), lookup); err == nil {
		t.Errorf("expected replay rejection on second use of same jti")
	}

	// wrong audience
	badTok, _ := jwt.NewBuilder().
		Issuer(cli.ClientID).Subject(cli.ClientID).
		Audience([]string{"https://wrong.example/token"}).
		IssuedAt(now).Expiration(now.Add(time.Minute)).JwtID("jti-2").Build()
	badSigned, _ := jwt.Sign(badTok, jwt.WithKey(jwa.ES256, priv))
	rBad := mkForm(url.Values{
		"client_assertion_type": {clientauth.JWTAssertionType},
		"client_assertion":      {string(badSigned)},
	})
	if _, err := clientauth.NewPrivateKeyJWTMethod(tokenEP, &inMemJTI{}).
		Authenticate(context.Background(), rBad, lookup); err == nil {
		t.Errorf("expected aud rejection")
	}

	// keep jws import alive
	_ = jws.Sign
}

// genECKey returns a fresh ECDSA P-256 *ecdsa.PrivateKey as `any` so it can
// flow into jwk.FromRaw without leaking the import here.
func genECKey(t *testing.T) any {
	t.Helper()
	priv, err := generateECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
