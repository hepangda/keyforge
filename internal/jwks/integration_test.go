//go:build integration

package jwks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtpkg "github.com/lestrrat-go/jwx/v2/jwt"

	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/httpx/oidc"
	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/logging"
	"github.com/hepangda/keyforge/internal/testsupport"
)

// fakeClock is a thread-safe wall clock that tests can advance.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func mustEnvelope(t *testing.T) *kcrypto.Envelope {
	t.Helper()
	kek := bytes.Repeat([]byte{0x42}, 32)
	env, err := kcrypto.NewEnvelope(kek)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestPostgresStoreEnsureActiveAndSign(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := jwks.NewPostgresStore(fx.Pool, mustEnvelope(t), clk)

	k1, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig)
	if err != nil {
		t.Fatal(err)
	}
	if k1.PrivateKey == nil {
		t.Fatal("expected hydrated private key")
	}

	// Second call must return the SAME key (idempotent).
	k1b, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig)
	if err != nil {
		t.Fatal(err)
	}
	if k1.ID != k1b.ID || k1.KID != k1b.KID {
		t.Fatalf("EnsureActive not idempotent: %s vs %s", k1.KID, k1b.KID)
	}

	// Sign-then-verify round trip via jwx.
	signer := jwks.NewSigner(store)
	tok, err := jwtpkg.NewBuilder().
		Issuer("https://keyforge.test").
		Subject("user-1").
		IssuedAt(clk.Now()).
		Expiration(clk.Now().Add(5 * time.Minute)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignJWT(ctx, uuid.Nil, tok)
	if err != nil {
		t.Fatal(err)
	}

	set, err := store.PublicSet(ctx, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := jwtpkg.Parse(
		[]byte(signed),
		jwtpkg.WithKeySet(set),
		jwtpkg.WithValidate(true),
		jwtpkg.WithClock(jwtpkg.ClockFunc(clk.Now)),
	)
	if err != nil {
		t.Fatalf("verify signed jwt: %v", err)
	}
	if verified.Subject() != "user-1" {
		t.Errorf("sub = %q, want user-1", verified.Subject())
	}
}

func TestPostgresStoreRotation(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := jwks.NewPostgresStore(fx.Pool, mustEnvelope(t), clk)

	k1, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig)
	if err != nil {
		t.Fatal(err)
	}

	k2, err := store.Rotate(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig)
	if err != nil {
		t.Fatal(err)
	}
	if k2.KID == k1.KID {
		t.Fatal("Rotate did not produce a new kid")
	}

	// The active key is now k2.
	cur, err := store.Active(ctx, uuid.Nil, jwks.UseSig)
	if err != nil {
		t.Fatal(err)
	}
	if cur.KID != k2.KID {
		t.Fatalf("active kid = %s, want %s", cur.KID, k2.KID)
	}

	// JWKS endpoint still serves k1 (rotated, retention window) alongside k2.
	set, err := store.PublicSet(ctx, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	kids := setKIDs(t, set)
	if !contains(kids, k1.KID) || !contains(kids, k2.KID) {
		t.Errorf("JWKS missing kids: got %v want both %s and %s", kids, k1.KID, k2.KID)
	}
}

func TestRotatorRotatesPastAge(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := jwks.NewPostgresStore(fx.Pool, mustEnvelope(t), clk)

	r, err := jwks.NewRotator(jwks.RotatorConfig{
		Store:             store,
		Clock:             clk,
		Logger:            slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)),
		DefaultAlg:        kcrypto.AlgEdDSA,
		RotateAfter:       90 * 24 * time.Hour,
		RetainAfterRotate: 30 * 24 * time.Hour,
		Interval:          1 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: no key yet — should create one.
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	k1, err := store.Active(ctx, uuid.Nil, jwks.UseSig)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Alg != kcrypto.AlgEdDSA {
		t.Errorf("alg = %q, want EdDSA", k1.Alg)
	}

	// Step 2: time hasn't moved, no rotation.
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	k1b, _ := store.Active(ctx, uuid.Nil, jwks.UseSig)
	if k1b.KID != k1.KID {
		t.Errorf("unexpected rotation on second step: %s -> %s", k1.KID, k1b.KID)
	}

	// Step 3: advance past rotation window, expect new active key.
	clk.Advance(91 * 24 * time.Hour)
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	k2, _ := store.Active(ctx, uuid.Nil, jwks.UseSig)
	if k2.KID == k1.KID {
		t.Errorf("rotation did not produce a new kid after %v", 91*24*time.Hour)
	}

	// Both still appear in PublicSet.
	set, err := store.PublicSet(ctx, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	kids := setKIDs(t, set)
	if !contains(kids, k1.KID) || !contains(kids, k2.KID) {
		t.Errorf("PublicSet kids = %v, want both rotated + active", kids)
	}

	// Step 4: advance well past retention, rotated key should be swept out.
	clk.Advance(60 * 24 * time.Hour)
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	set, err = store.PublicSet(ctx, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	kids = setKIDs(t, set)
	if contains(kids, k1.KID) {
		t.Errorf("retired key %s should be swept out of PublicSet, got %v", k1.KID, kids)
	}
}

func TestJWKSHandlerServesActiveKey(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := jwks.NewPostgresStore(fx.Pool, mustEnvelope(t), clk)

	if _, err := store.EnsureActive(ctx, uuid.Nil, kcrypto.AlgES256, jwks.UseSig); err != nil {
		t.Fatal(err)
	}

	h := oidc.NewJWKSHandler(store, slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)), nil)
	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/jwks.json", h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rsp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", rsp.StatusCode)
	}
	if ct := rsp.Header.Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Errorf("content-type = %q", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(rsp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	keys, ok := body["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("no keys in response: %+v", body)
	}
	first, _ := keys[0].(map[string]any)
	if first["kid"] == "" || first["alg"] != "ES256" || first["use"] != "sig" {
		t.Errorf("unexpected first key: %+v", first)
	}
	// Critical: no private parameters in the published JWK.
	for _, k := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, present := first[k]; present {
			t.Errorf("private parameter %q leaked into JWKS response", k)
		}
	}
}

func TestPrivateMaterialNeverLogged(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := jwks.NewPostgresStore(fx.Pool, mustEnvelope(t), clk)

	var buf bytes.Buffer
	logger := logging.New(logging.Options{Level: slog.LevelDebug, Format: "json", Writer: &buf})

	r, err := jwks.NewRotator(jwks.RotatorConfig{
		Store: store, Clock: clk, Logger: logger,
		DefaultAlg: kcrypto.AlgRS256, RotateAfter: time.Hour, Interval: time.Minute,
		RetainAfterRotate: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, forbidden := range []string{"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE", "private_pem"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log output leaked %q:\n%s", forbidden, out)
		}
	}
}

func setKIDs(t *testing.T, set jwk.Set) []string {
	t.Helper()
	out := make([]string, 0, set.Len())
	for it := set.Keys(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key, _ := pair.Value.(jwk.Key)
		out = append(out, key.KeyID())
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// keep these imports referenced even when only some tests use them
var (
	_ = jwa.RS256
	_ = jws.Sign
)
