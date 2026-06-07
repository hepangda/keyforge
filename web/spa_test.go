package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSPAHistoryFallback(t *testing.T) {
	h, err := NewSPA()
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Root and deep links both return index.html.
	for _, path := range []string{"/portal", "/portal/", "/portal/sessions", "/admin/clients/123"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("ct=%q", ct)
			}
			if !strings.Contains(w.Body.String(), "<title>") {
				t.Fatalf("body doesn't look like html")
			}
		})
	}
}

func TestSPAMethodNotAllowed(t *testing.T) {
	h, err := NewSPA()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/portal", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestSPAMimeForKnownAssets(t *testing.T) {
	cases := map[string]string{
		"app.js":         "application/javascript; charset=utf-8",
		"app.css":        "text/css; charset=utf-8",
		"icon.svg":       "image/svg+xml",
		"font.woff2":     "font/woff2",
		"meta.json":      "application/json; charset=utf-8",
		"index.html":     "text/html; charset=utf-8",
		"unknown.binary": "application/octet-stream",
	}
	for name, want := range cases {
		if got := mimeFor(name); got != want {
			t.Errorf("mimeFor(%q) = %q want %q", name, got, want)
		}
	}
}
