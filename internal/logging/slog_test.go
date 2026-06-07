package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactSensitiveKeys(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lg := New(Options{Level: slog.LevelDebug, Format: "json", Writer: &buf})

	lg.Info(
		"test",
		slog.String("password", "hunter2"),
		slog.String("token", "very-secret"),
		slog.String("refresh_token", "rt-very-secret"),
		slog.String("id_token", "eyJ..."),
		slog.String("code", "abc"),
		slog.String("client_secret", "csecret"),
		slog.String("assertion", "asrt"),
		slog.String("private_key", "BEGIN PRIVATE KEY"),
		slog.String("private_pem", "BEGIN PRIVATE KEY"),
		slog.String("secret_dek", "dek"),
		slog.String("authorization", "Bearer xyz"),
		slog.String("DPoP", "dpop-proof"),
		slog.String("safe_field", "visible"),
	)

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	for _, k := range []string{
		"password", "token", "refresh_token", "id_token", "code",
		"client_secret", "assertion", "private_key", "private_pem", "secret_dek",
		"authorization", "DPoP",
	} {
		v, ok := out[k]
		if !ok {
			t.Errorf("key %q missing from log output", k)
			continue
		}
		if v != Redacted {
			t.Errorf("key %q should be redacted, got %q", k, v)
		}
	}
	if out["safe_field"] != "visible" {
		t.Errorf("safe_field should pass through, got %v", out["safe_field"])
	}
	if strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "BEGIN PRIVATE KEY") {
		t.Errorf("redacted value leaked into log: %s", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"unknown": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
