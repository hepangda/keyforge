package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandlerLiveAndReady(t *testing.T) {
	t.Parallel()
	h := NewHealthHandler()
	h.AddLiveness(ProbeFunc{N: "self", F: func(context.Context) error { return nil }})
	h.AddReadiness(ProbeFunc{N: "db", F: func(context.Context) error { return nil }})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Live)
	mux.HandleFunc("GET /readyz", h.Ready)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, p := range []string{"/healthz", "/readyz"} {
		rsp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", p, rsp.StatusCode)
		}
		var body healthResponse
		if err := json.NewDecoder(rsp.Body).Decode(&body); err != nil {
			t.Fatalf("decode %s: %v", p, err)
		}
		rsp.Body.Close()
		if body.Status != "ok" {
			t.Errorf("GET %s: status field = %q, want ok", p, body.Status)
		}
	}
}

func TestHealthHandlerFailingProbeReturns503(t *testing.T) {
	t.Parallel()
	h := NewHealthHandler()
	h.AddReadiness(ProbeFunc{N: "db", F: func(context.Context) error { return errors.New("dead") }})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.Ready(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	var body healthResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "fail" {
		t.Errorf("status field = %q, want fail", body.Status)
	}
	if len(body.Probes) != 1 || body.Probes[0].Error != "dead" {
		t.Errorf("unexpected probes: %+v", body.Probes)
	}
}
