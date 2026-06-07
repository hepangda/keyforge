package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/mtls"
	"github.com/hepangda/keyforge/internal/storage/clients"
)

func mkTLSReq(values url.Values, cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

// makeCert produces a self-signed cert + the underlying private key for a
// given subject DN.
func makeCert(t *testing.T, subject pkix.Name) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
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
	return cert, priv
}

func TestTLSClientAuthSuccessAndDNMismatch(t *testing.T) {
	t.Parallel()
	subject := pkix.Name{CommonName: "alice", Organization: []string{"Acme"}}
	cert, _ := makeCert(t, subject)

	cli := &clients.Client{
		ID: uuid.New(), TenantID: uuid.New(), ClientID: "cli-mtls",
		ClientType:              clients.TypeConfidential,
		TokenEndpointAuthMethod: string(clientauth.MethodTLSClientAuth),
		TLSClientAuthSubjectDN:  cert.Subject.String(),
	}
	lookup := &fakeLookup{byClientID: map[string]*clients.Client{cli.ClientID: cli}}
	m := clientauth.NewTLSClientAuthMethod(mtls.DirectExtractor{})

	// good
	r := mkTLSReq(url.Values{"client_id": {cli.ClientID}}, cert)
	if _, err := m.Authenticate(context.Background(), r, lookup); err != nil {
		t.Fatalf("good tls auth: %v", err)
	}

	// wrong DN
	cli.TLSClientAuthSubjectDN = "CN=bob,O=Other"
	if _, err := m.Authenticate(context.Background(), r, lookup); err == nil {
		t.Errorf("expected DN mismatch")
	}
}

func TestSelfSignedTLSAuthMatchByThumbprint(t *testing.T) {
	t.Parallel()
	cert, _ := makeCert(t, pkix.Name{CommonName: "self-spa"})

	// Construct a JWK Set containing the cert's public key.
	jk, err := jwk.FromRaw(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jk.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatal(err)
	}
	if err := jk.Set(jwk.KeyIDKey, "client-self"); err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	_ = set.AddKey(jk)
	js, _ := json.Marshal(set)

	cli := &clients.Client{
		ID: uuid.New(), TenantID: uuid.New(), ClientID: "cli-self",
		ClientType:              clients.TypeConfidential,
		TokenEndpointAuthMethod: string(clientauth.MethodSelfSignedTLSAuth),
		JWKS:                    js,
	}
	lookup := &fakeLookup{byClientID: map[string]*clients.Client{cli.ClientID: cli}}
	m := clientauth.NewSelfSignedTLSClientAuthMethod(mtls.DirectExtractor{})

	r := mkTLSReq(url.Values{"client_id": {cli.ClientID}}, cert)
	if _, err := m.Authenticate(context.Background(), r, lookup); err != nil {
		t.Fatalf("self-signed tls auth: %v", err)
	}

	// Different cert => mismatch.
	cert2, _ := makeCert(t, pkix.Name{CommonName: "other"})
	r2 := mkTLSReq(url.Values{"client_id": {cli.ClientID}}, cert2)
	if _, err := m.Authenticate(context.Background(), r2, lookup); err == nil {
		t.Errorf("expected thumbprint mismatch")
	}
}

func TestMTLSDirectExtractor(t *testing.T) {
	t.Parallel()
	cert, _ := makeCert(t, pkix.Name{CommonName: "extract-test"})
	r := mkTLSReq(nil, cert)
	got, err := (mtls.DirectExtractor{}).Extract(r)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got.Subject.CommonName != "extract-test" {
		t.Errorf("CN = %q", got.Subject.CommonName)
	}

	// no peer certs => ErrNoClientCert
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := (mtls.DirectExtractor{}).Extract(plain); err == nil {
		t.Errorf("expected ErrNoClientCert without TLS")
	}
}
