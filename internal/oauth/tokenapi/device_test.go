//go:build integration

package tokenapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/auth/password"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/device"
	"github.com/hepangda/keyforge/internal/oauth/tokenapi"
	"github.com/hepangda/keyforge/internal/oauth/tokens"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

type deviceRig struct {
	tenant *tenants.Tenant
	client *clients.Client
	user   *users.User
	srv    *httptest.Server
	q      *db.Queries
}

func setupDevice(t *testing.T) *deviceRig {
	t.Helper()
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	tenantsRepo := tenants.New(fx.Pool)
	tenant, err := tenantsRepo.Create(ctx, "dev", "DEV", "https://dev.test")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	clientsRepo := clients.New(fx.Pool)
	hash, _ := clientauth.HashSecret("dev-secret")
	cli, err := clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "tv-app",
		ClientType:              clients.TypeConfidential,
		Name:                    "TV",
		ClientSecretHash:        hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
		GrantTypes:              []string{device.GrantType},
		Scopes:                  []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatal(err)
	}

	usersRepo := users.New(fx.Pool)
	user, err := usersRepo.Create(ctxT, users.CreateInput{
		Email: "tv-user@dev.test", EmailVerified: true,
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

	issuer, err := tokens.NewIssuer(tokens.Config{
		Pool: fx.Pool, Signer: signer, UsersRepo: usersRepo,
		Issuer: "https://dev.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := clientauth.NewAuthenticator(
		&clientLookup{repo: clientsRepo, tid: tenant.ID, pool: fx.Pool},
		clientauth.NewSecretBasicMethod(),
	)

	tokenH, err := tokenapi.New(tokenapi.Config{
		Queries:               db.New(fx.Pool),
		Issuer:                issuer,
		Authenticator:         auth,
		ClientsRepo:           clientsRepo,
		UsersRepo:             usersRepo,
		TenantFor:             tenantFor,
		DevicePollMinInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	deviceH, err := device.New(device.Config{
		Queries:       db.New(fx.Pool),
		Authenticator: auth,
		TenantFor:     tenantFor,
		CodeTTL:       30 * time.Second,
		PollInterval:  200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	tokenH.Routes(mux)
	deviceH.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &deviceRig{
		tenant: tenant, client: cli, user: user,
		srv: srv, q: db.New(fx.Pool),
	}
}

func TestDeviceFlowHappyPath(t *testing.T) {
	r := setupDevice(t)

	// 1) /device_authorization issues codes.
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/device_authorization",
		strings.NewReader(url.Values{
			"scope": {"openid profile"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.client.ClientID, "dev-secret")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization status %d: %s", rsp.StatusCode, body)
	}
	var da device.AuthorizeResponse
	_ = json.Unmarshal(body, &da)
	if da.DeviceCode == "" || da.UserCode == "" {
		t.Fatalf("missing codes: %+v", da)
	}

	// 2) Polling before approval returns authorization_pending.
	pollReq, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type":  {device.GrantType},
			"device_code": {da.DeviceCode},
		}.Encode()))
	pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pollReq.SetBasicAuth(r.client.ClientID, "dev-secret")
	pollRsp, _ := http.DefaultClient.Do(pollReq)
	pollBody, _ := io.ReadAll(pollRsp.Body)
	pollRsp.Body.Close()
	if !strings.Contains(string(pollBody), "authorization_pending") {
		t.Fatalf("expected authorization_pending, got %d %s", pollRsp.StatusCode, pollBody)
	}

	// 3) User visits /device, enters the user_code, approves.
	verifyReq, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/device",
		strings.NewReader(url.Values{
			"user_code": {da.UserCode},
			"decision":  {"allow"},
		}.Encode()))
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.Header.Set("X-Test-UserID", r.user.ID.String())
	vr, _ := http.DefaultClient.Do(verifyReq)
	vrBody, _ := io.ReadAll(vr.Body)
	vr.Body.Close()
	if vr.StatusCode != http.StatusOK {
		t.Fatalf("verify status %d body %s", vr.StatusCode, vrBody)
	}

	// 4) Wait past minInterval, then poll again — expect a successful
	// token response.
	time.Sleep(250 * time.Millisecond)
	pollReq2, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type":  {device.GrantType},
			"device_code": {da.DeviceCode},
		}.Encode()))
	pollReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pollReq2.SetBasicAuth(r.client.ClientID, "dev-secret")
	finalRsp, err := http.DefaultClient.Do(pollReq2)
	if err != nil {
		t.Fatal(err)
	}
	finalBody, _ := io.ReadAll(finalRsp.Body)
	finalRsp.Body.Close()
	if finalRsp.StatusCode != http.StatusOK {
		t.Fatalf("token poll after approval: status %d body %s",
			finalRsp.StatusCode, finalBody)
	}
	var tr tokens.Response
	_ = json.Unmarshal(finalBody, &tr)
	if tr.AccessToken == "" {
		t.Fatalf("missing access_token: %s", finalBody)
	}
	if tr.IDToken == "" {
		t.Errorf("expected id_token (openid scope was requested)")
	}

	// 5) The same device_code cannot be redeemed twice.
	again, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type":  {device.GrantType},
			"device_code": {da.DeviceCode},
		}.Encode()))
	again.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	again.SetBasicAuth(r.client.ClientID, "dev-secret")
	a2, _ := http.DefaultClient.Do(again)
	a2.Body.Close()
	if a2.StatusCode == http.StatusOK {
		t.Errorf("device_code replay should fail")
	}
}

func TestDeviceFlowDenied(t *testing.T) {
	r := setupDevice(t)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/device_authorization", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.client.ClientID, "dev-secret")
	rsp, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	var da device.AuthorizeResponse
	_ = json.Unmarshal(body, &da)

	deny, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/device",
		strings.NewReader(url.Values{
			"user_code": {da.UserCode},
			"decision":  {"deny"},
		}.Encode()))
	deny.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deny.Header.Set("X-Test-UserID", r.user.ID.String())
	denyRsp, _ := http.DefaultClient.Do(deny)
	denyRsp.Body.Close()

	time.Sleep(250 * time.Millisecond)
	pollReq, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type":  {device.GrantType},
			"device_code": {da.DeviceCode},
		}.Encode()))
	pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pollReq.SetBasicAuth(r.client.ClientID, "dev-secret")
	finalRsp, _ := http.DefaultClient.Do(pollReq)
	finalBody, _ := io.ReadAll(finalRsp.Body)
	finalRsp.Body.Close()
	if !strings.Contains(string(finalBody), "access_denied") {
		t.Fatalf("expected access_denied, got %d %s", finalRsp.StatusCode, finalBody)
	}
}
