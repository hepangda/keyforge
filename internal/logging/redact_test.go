package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestRedactionCoversAllSensitiveKeys enumerates every key the plan
// commits to scrubbing and asserts each one is replaced with the
// Redacted sentinel. This is the load-bearing test referenced by the
// M20 milestone.
func TestRedactionCoversAllSensitiveKeys(t *testing.T) {
	cases := []string{
		"password", "passwd", "secret", "client_secret",
		"token", "access_token", "refresh_token", "id_token",
		"code", "code_verifier",
		"assertion", "client_assertion",
		"authorization", "cookie", "set-cookie",
		"dpop", "x-forwarded-client-cert",
		// prefix-matched
		"private_key", "secret_inner", "password_hash", "token_meta",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			buf := &bytes.Buffer{}
			log := New(Options{Format: "json", Writer: buf, Level: slog.LevelInfo})
			log.Info("evt", slog.String(key, "supersecret-payload-12345"))
			line := buf.Bytes()
			var got map[string]any
			if err := json.Unmarshal(line, &got); err != nil {
				t.Fatalf("parse: %v\n%s", err, line)
			}
			val, ok := got[key].(string)
			if !ok {
				t.Fatalf("key %q missing or not string: %v", key, got[key])
			}
			if val != Redacted {
				t.Fatalf("key %q not redacted: %q", key, val)
			}
			if strings.Contains(string(line), "supersecret-payload-12345") {
				t.Fatalf("raw value leaked into log line: %s", line)
			}
		})
	}
}

// TestRedactionLeavesBenignKeysAlone confirms we don't over-redact.
func TestRedactionLeavesBenignKeysAlone(t *testing.T) {
	buf := &bytes.Buffer{}
	log := New(Options{Format: "json", Writer: buf, Level: slog.LevelInfo})
	log.Info("evt",
		slog.String("client_id", "demo-client"),
		slog.String("tenant_id", "abc"),
		slog.String("email", "user@example.com"),
	)
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, key := range []string{"client_id", "tenant_id", "email"} {
		if got[key] == Redacted {
			t.Fatalf("benign key %q was redacted", key)
		}
	}
}
