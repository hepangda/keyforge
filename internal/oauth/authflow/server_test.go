//go:build integration

package authflow_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// testServer is a tiny alias so the test helper signature reads naturally.
type testServer = httptest.Server

// startServer creates an httptest.NewServer and registers cleanup.
func startServer(t *testing.T, mux http.Handler) *testServer {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
