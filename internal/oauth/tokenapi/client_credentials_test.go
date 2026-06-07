//go:build integration

package tokenapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// addClientResource is a tiny helper to seed the new client_allowed_resources
// table from a test; we don't want to expose a dedicated repo method just
// for this.
func addClientResource(t *testing.T, q *db.Queries, tid, cliPK uuid.UUID, resource string) {
	t.Helper()
	if err := q.AddClientAllowedResource(context.Background(), db.AddClientAllowedResourceParams{
		TenantID: tid, ClientID: cliPK, Resource: resource,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentialsGrantHappyPath(t *testing.T) {
	r := setup(t)
	ctx := context.Background()

	// Register a confidential client with a known secret and scope set.
	hash, err := clientauth.HashSecret("svc-secret")
	if err != nil {
		t.Fatal(err)
	}
	ctxT := postgres.ContextWithTenant(ctx, r.tenant.ID)
	cli, err := r.clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "svc-1",
		ClientType:              clients.TypeConfidential,
		Name:                    "Background worker",
		ClientSecretHash:        hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"orders.read", "orders.write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	addClientResource(t, r.queries, r.tenant.ID, cli.ID, "https://api.example/")

	// 1) good request: subset of scopes + registered resource
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type": {"client_credentials"},
			"scope":      {"orders.read"},
			"resource":   {"https://api.example/"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc-1", "svc-secret")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rsp.Body)
		t.Fatalf("token status %d: %s", rsp.StatusCode, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Refresh     string `json:"refresh_token"`
		ID          string `json:"id_token"`
	}
	_ = json.NewDecoder(rsp.Body).Decode(&tr)
	rsp.Body.Close()
	if tr.AccessToken == "" {
		t.Fatal("missing access_token")
	}
	if tr.Refresh != "" || tr.ID != "" {
		t.Errorf("client_credentials must not issue RT or ID token: %+v", tr)
	}
	if tr.Scope != "orders.read" {
		t.Errorf("scope = %q", tr.Scope)
	}

	// 2) introspecting the AT must show the resource as audience
	intReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		r.srv.URL+"/oauth/introspect",
		strings.NewReader(url.Values{
			"token": {tr.AccessToken},
		}.Encode()))
	intReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	intReq.SetBasicAuth("svc-1", "svc-secret")
	intRsp, err := http.DefaultClient.Do(intReq)
	if err != nil {
		t.Fatal(err)
	}
	var intro map[string]any
	_ = json.NewDecoder(intRsp.Body).Decode(&intro)
	intRsp.Body.Close()
	if intro["active"] != true {
		t.Fatalf("introspect: %+v", intro)
	}
	auds, ok := intro["aud"].([]any)
	if !ok || len(auds) != 1 || auds[0] != "https://api.example/" {
		t.Errorf("aud = %v, want [https://api.example/]", intro["aud"])
	}
}

func TestClientCredentialsRejectsUnregisteredScope(t *testing.T) {
	r := setup(t)
	ctx := context.Background()

	hash, _ := clientauth.HashSecret("svc-secret")
	ctxT := postgres.ContextWithTenant(ctx, r.tenant.ID)
	_, err := r.clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "svc-strict",
		ClientType:              clients.TypeConfidential,
		Name:                    "Strict",
		ClientSecretHash:        hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"orders.read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// orders.write is not registered — must be rejected.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type": {"client_credentials"},
			"scope":      {"orders.read orders.write"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc-strict", "svc-secret")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400. body=%s", rsp.StatusCode, body)
	}
	if !strings.Contains(string(body), "invalid_scope") {
		t.Errorf("expected invalid_scope error, got %s", body)
	}
}

func TestClientCredentialsRejectsUnregisteredResource(t *testing.T) {
	r := setup(t)
	ctx := context.Background()

	hash, _ := clientauth.HashSecret("svc-secret")
	ctxT := postgres.ContextWithTenant(ctx, r.tenant.ID)
	cli, _ := r.clientsRepo.Create(ctxT, clients.CreateInput{
		ClientID:                "svc-res",
		ClientType:              clients.TypeConfidential,
		Name:                    "Resource test",
		ClientSecretHash:        hash,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"thing"},
	})
	addClientResource(t, r.queries, r.tenant.ID, cli.ID, "https://allowed.example/")

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type": {"client_credentials"},
			"scope":      {"thing"},
			"resource":   {"https://forbidden.example/"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc-res", "svc-secret")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400. body=%s", rsp.StatusCode, body)
	}
	if !strings.Contains(string(body), "invalid_target") {
		t.Errorf("expected invalid_target, got %s", body)
	}
}

func TestClientCredentialsRejectsPublicClient(t *testing.T) {
	r := setup(t)
	ctx := context.Background()

	// `setup` already seeded a public client `spa`. Confirm it cannot use the
	// client_credentials grant even when its registered methods say `none`.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		r.srv.URL+"/oauth/token",
		strings.NewReader(url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {r.client.ClientID},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400. body=%s", rsp.StatusCode, body)
	}
}
