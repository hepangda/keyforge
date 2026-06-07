// Package oidc hosts the HTTP handlers for keyforge's OIDC-flavored well-known
// endpoints: discovery, JWKS, and the future logout/endsession routes.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/httpx"
	"github.com/hepangda/keyforge/internal/jwks"
)

// JWKSHandler serves GET /.well-known/jwks.json. The active key plus any
// rotated keys still in their retention window are published; private
// material is never serialized.
type JWKSHandler struct {
	store  jwks.Store
	logger *slog.Logger
	// tenantResolver maps a request to its tenant scope. M3 uses a fixed
	// global (uuid.Nil) keyset; later milestones inject per-tenant resolution
	// driven by hostname or path prefix.
	tenantResolver func(*http.Request) uuid.UUID
}

// NewJWKSHandler constructs a handler. resolver may be nil to always serve
// the global keyset.
func NewJWKSHandler(store jwks.Store, logger *slog.Logger, resolver func(*http.Request) uuid.UUID) *JWKSHandler {
	if resolver == nil {
		resolver = func(*http.Request) uuid.UUID { return uuid.Nil }
	}
	return &JWKSHandler{store: store, logger: logger, tenantResolver: resolver}
}

// ServeHTTP implements http.Handler.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID := h.tenantResolver(r)
	set, err := h.store.PublicSet(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			http.Error(w, "request cancelled", http.StatusServiceUnavailable)
			return
		}
		h.logger.LogAttrs(
			r.Context(), slog.LevelError, "publish jwks failed",
			slog.Any("error", err),
			slog.String("request_id", httpx.RequestIDFromContext(r.Context())),
		)
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		// The client likely closed the connection; nothing we can do.
		h.logger.Debug("write jwks failed", slog.Any("error", err))
	}
}
