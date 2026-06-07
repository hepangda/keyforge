package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleYAML = `
server:
  addr: :8080
  admin_addr: :9090
  read_header_timeout: 10s
  idle_timeout: 120s
  shutdown_timeout: 30s
database:
  url: postgres://user:pass@localhost:5432/keyforge?sslmode=disable
  max_open_conns: 20
  max_idle_conns: 5
  conn_max_lifetime: 30m
jwks:
  master_key: 0123456789abcdef0123456789abcdef
  rotate_after: 2160h
  retain_after_rotate: 720h
  default_alg: RS256
oidc:
  issuer: https://auth.example.test
  access_token_ttl: 15m
  refresh_token_ttl: 720h
  id_token_ttl: 15m
  authorize_code_ttl: 60s
  par_request_uri_ttl: 90s
  device_code_ttl: 10m
  dpop_proof_max_skew: 60s
  session_ttl: 24h
  session_cookie_name: __Host-kf_sid
logging:
  level: info
  format: json
`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "keyforge.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFromYAML(t *testing.T) {
	path := writeTemp(t, sampleYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Addr != ":8080" {
		t.Errorf("server.addr = %q, want :8080", cfg.Server.Addr)
	}
	if cfg.OIDC.AccessTokenTTL != 15*time.Minute {
		t.Errorf("oidc.access_token_ttl = %v, want 15m", cfg.OIDC.AccessTokenTTL)
	}
	if cfg.JWKS.DefaultAlg != "RS256" {
		t.Errorf("jwks.default_alg = %q", cfg.JWKS.DefaultAlg)
	}
}

func TestEnvOverrides(t *testing.T) {
	path := writeTemp(t, sampleYAML)
	t.Setenv("KEYFORGE_SERVER__ADDR", ":7777")
	t.Setenv("KEYFORGE_OIDC__ISSUER", "https://override.example")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Addr != ":7777" {
		t.Errorf("server.addr = %q, want :7777 (env override)", cfg.Server.Addr)
	}
	if cfg.OIDC.Issuer != "https://override.example" {
		t.Errorf("oidc.issuer = %q, want override", cfg.OIDC.Issuer)
	}
}

func TestValidationCatchesMissing(t *testing.T) {
	// Missing required fields like database.url should fail validation.
	bad := `server:
  addr: :8080
  admin_addr: :9090
  read_header_timeout: 10s
  idle_timeout: 120s
  shutdown_timeout: 30s`
	path := writeTemp(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error, got nil")
	} else if !strings.Contains(err.Error(), "validate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidationRejectsBadAlg(t *testing.T) {
	bad := strings.Replace(sampleYAML, "default_alg: RS256", "default_alg: NOTANALG", 1)
	path := writeTemp(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error for bad alg, got nil")
	}
}
