package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddlewareGenerates(t *testing.T) {
	t.Parallel()
	var seen string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(w, r)

	if seen == "" {
		t.Fatal("request id not injected into context")
	}
	if got := w.Header().Get(RequestIDHeader); got != seen {
		t.Errorf("response header %q does not echo context value %q", got, seen)
	}
}

func TestRequestIDMiddlewareRespectsInbound(t *testing.T) {
	t.Parallel()
	const inbound = "deadbeefdeadbeefdeadbeefdeadbeef"
	var seen string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set(RequestIDHeader, inbound)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != inbound {
		t.Fatalf("request id = %q, want %q", seen, inbound)
	}
}

func TestRealIPHonorsTrustedProxies(t *testing.T) {
	t.Parallel()
	cidrs, err := ParseCIDRs([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	h := RealIP(cidrs)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RealIPFromContext(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "127.0.0.1:5678"
	r.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != "203.0.113.10" {
		t.Errorf("real ip = %q, want 203.0.113.10", seen)
	}
}

func TestRealIPIgnoresUntrustedXFF(t *testing.T) {
	t.Parallel()
	var seen string
	h := RealIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RealIPFromContext(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != "203.0.113.5" {
		t.Errorf("real ip = %q, want 203.0.113.5 (XFF must be ignored without trusted proxies)", seen)
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	t.Parallel()
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(context.Background())
	h.ServeHTTP(w, r)

	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
}
