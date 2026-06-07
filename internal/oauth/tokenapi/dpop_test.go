//go:build integration

package tokenapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/oauth/dpop"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/oauth/tokens"
)

// dpopClientKey generates an EC client signing key and its public JWK.
func dpopClientKey(t *testing.T) (jwk.Key, jwk.Key) {
	t.Helper()
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
	pubJWK, err := jwk.PublicKeyOf(privJWK)
	if err != nil {
		t.Fatal(err)
	}
	return privJWK, pubJWK
}

// makeDPoPProof signs a proof for the given method+url, optionally binding
// to an access token via the ath claim.
func makeDPoPProof(t *testing.T, priv, pub jwk.Key, method, url, accessToken string) string {
	t.Helper()
	now := time.Now()
	b := jwt.NewBuilder().
		IssuedAt(now).
		JwtID(uuid.NewString()).
		Claim("htm", method).
		Claim("htu", url)
	if accessToken != "" {
		b = b.Claim("ath", dpop.ATHFor(accessToken))
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.TypeKey, "dpop+jwt")
	_ = hdr.Set(jws.JWKKey, pub)
	_ = hdr.Set(jws.AlgorithmKey, jwa.ES256)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestDPoPBoundTokensAndUserInfo(t *testing.T) {
	r := setup(t)

	// Drive auth-code flow to obtain a code, then exchange with a DPoP proof.
	verifier, _ := pkce.GenerateVerifier()
	challenge := pkce.DeriveChallenge(verifier)
	code := authCodeRound(
		t, r.srv,
		r.client.ClientID, "http://127.0.0.1/callback",
		"openid profile offline_access", "xyz", challenge,
	)
	if code == "" {
		t.Fatal("no code")
	}

	priv, pub := dpopClientKey(t)
	tokenURL := r.srv.URL + "/oauth/token"
	proof := makeDPoPProof(t, priv, pub, http.MethodPost, tokenURL, "")

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, tokenURL,
		strings.NewReader(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://127.0.0.1/callback"},
			"client_id":     {r.client.ClientID},
			"code_verifier": {verifier},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(dpop.HeaderName, proof)

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("token status %d: %s", rsp.StatusCode, body)
	}
	var tr tokens.Response
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatal(err)
	}
	if tr.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want DPoP", tr.TokenType)
	}

	// 1) /userinfo without DPoP must fail.
	uiURL := r.srv.URL + "/oauth/userinfo"
	bare, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, uiURL, nil)
	bare.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	br, _ := http.DefaultClient.Do(bare)
	br.Body.Close()
	if br.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo without DPoP: status = %d, want 401", br.StatusCode)
	}

	// 2) /userinfo with a fresh DPoP proof carrying ath must succeed.
	uiProof := makeDPoPProof(t, priv, pub, http.MethodGet, uiURL, tr.AccessToken)
	ok, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, uiURL, nil)
	ok.Header.Set("Authorization", "DPoP "+tr.AccessToken)
	ok.Header.Set(dpop.HeaderName, uiProof)
	okR, err := http.DefaultClient.Do(ok)
	if err != nil {
		t.Fatal(err)
	}
	bodyOK, _ := io.ReadAll(okR.Body)
	okR.Body.Close()
	if okR.StatusCode != http.StatusOK {
		t.Fatalf("userinfo with DPoP: status %d body %s", okR.StatusCode, bodyOK)
	}
	var ui map[string]any
	if err := json.Unmarshal(bodyOK, &ui); err != nil {
		t.Fatal(err)
	}
	if ui["sub"] == nil {
		t.Errorf("userinfo missing sub: %v", ui)
	}

	// 3) /userinfo with a DPoP proof signed by a DIFFERENT key must fail
	// (jkt mismatch).
	other, otherPub := dpopClientKey(t)
	otherProof := makeDPoPProof(t, other, otherPub, http.MethodGet, uiURL, tr.AccessToken)
	wrong, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, uiURL, nil)
	wrong.Header.Set("Authorization", "DPoP "+tr.AccessToken)
	wrong.Header.Set(dpop.HeaderName, otherProof)
	wr, _ := http.DefaultClient.Do(wrong)
	wr.Body.Close()
	if wr.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo with wrong-key DPoP: status = %d, want 401", wr.StatusCode)
	}
}
