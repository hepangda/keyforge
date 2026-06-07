package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hepangda/keyforge/internal/config"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

func minimalConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.Addr = freePort(t)
	cfg.Server.AdminAddr = freePort(t)
	cfg.Server.ShutdownTimeout = 5 * time.Second
	cfg.Database.URL = "postgres://example/keyforge?sslmode=disable"
	cfg.JWKS.MasterKey = "0123456789abcdef0123456789abcdef"
	cfg.OIDC.Issuer = "http://" + cfg.Server.Addr
	return cfg
}

func TestAppHealthAndVersionEndpoints(t *testing.T) {
	cfg := minimalConfig(t)
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()

	// wait until the public server is accepting connections
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", cfg.Server.Addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, p := range []string{"/healthz", "/readyz", "/version"} {
		rsp, err := http.Get("http://" + cfg.Server.Addr + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		if rsp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d", p, rsp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, rsp.Body)
		_ = rsp.Body.Close()
	}

	rsp, err := http.Get("http://" + cfg.Server.AdminAddr + "/version")
	if err != nil {
		t.Fatalf("GET admin /version: %v", err)
	}
	defer rsp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(rsp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["admin"] != true {
		t.Errorf("expected admin: true on admin port, got %v", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within shutdown timeout")
	}
}
