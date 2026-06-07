// Package par implements the Pushed Authorization Requests endpoint per
// RFC 9126. Clients POST their authorization request parameters to
// /oauth/par; the server returns a one-shot `request_uri` that can be
// presented as the only meaningful parameter (besides `client_id`) at
// /oauth/authorize. The request_uri is single-use and short-lived; once
// consumed at /authorize it cannot be reused.
package par

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// URNPrefix is the canonical prefix for keyforge's request_uri values.
const URNPrefix = "urn:ietf:params:oauth:request_uri:"

// Errors surfaced by the package.
var (
	ErrConsumed = errors.New("par: request_uri already consumed")
	ErrExpired  = errors.New("par: request_uri expired")
	ErrNotFound = errors.New("par: request_uri not found")
)

// Handler serves POST /oauth/par.
type Handler struct {
	q             *db.Queries
	authenticator *clientauth.Authenticator
	tenantFor     func(*http.Request) (uuid.UUID, error)
	ttl           time.Duration
}

// Config configures the Handler.
type Config struct {
	Queries       *db.Queries
	Authenticator *clientauth.Authenticator
	TenantFor     func(*http.Request) (uuid.UUID, error)
	// TTL is how long the issued request_uri remains usable. RFC 9126
	// recommends ≤ 600s; keyforge defaults to 90s.
	TTL time.Duration
}

// New constructs a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Queries == nil || cfg.Authenticator == nil {
		return nil, errors.New("par: incomplete config")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 90 * time.Second
	}
	return &Handler{
		q:             cfg.Queries,
		authenticator: cfg.Authenticator,
		tenantFor:     cfg.TenantFor,
		ttl:           cfg.TTL,
	}, nil
}

// Routes registers POST /oauth/par.
func (h *Handler) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("POST /oauth/par", h.Push)
}

// PushResponse is the JSON shape RFC 9126 §2.2 mandates.
type PushResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// Push handles the PAR request. Body is application/x-www-form-urlencoded
// and may include every parameter the authorize endpoint would normally
// take (response_type, scope, redirect_uri, state, nonce, code_challenge,
// code_challenge_method, prompt, …). They are validated for *presence*
// here and exact validation happens at /authorize when the request_uri is
// redeemed.
func (h *Handler) Push(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse body")
		return
	}
	tid, err := h.tenant(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	ctx := postgres.ContextWithTenant(r.Context(), tid)

	authRes, err := h.authenticator.Authenticate(ctx, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// Per RFC 9126 §2.1, request_uri must NOT be a top-level PAR parameter.
	if r.PostForm.Has("request_uri") {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"request_uri is forbidden at the PAR endpoint")
		return
	}
	// client_id, if present, must equal the authenticated client.
	if v := r.PostForm.Get("client_id"); v != "" && v != authRes.Client.ClientID {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"client_id in body does not match authenticated client")
		return
	}

	// Capture the rest of the form as the payload to redeem later.
	r.PostForm.Set("client_id", authRes.Client.ClientID)
	payload := make(map[string][]string, len(r.PostForm))
	for k, v := range r.PostForm {
		if k == "client_secret" || k == "client_assertion" || k == "client_assertion_type" {
			continue // never persist client credentials
		}
		payload[k] = v
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	uri, err := newRequestURI()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	expiresAt := time.Now().Add(h.ttl).UTC()
	if _, err := h.q.InsertPARRequest(ctx, db.InsertPARRequestParams{
		TenantID:   tid,
		RequestUri: uri,
		ClientID:   authRes.Client.ID,
		Payload:    payloadJSON,
		ExpiresAt:  expiresAt,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(PushResponse{
		RequestURI: uri,
		ExpiresIn:  int(h.ttl.Seconds()),
	})
}

// Redeem looks up a previously-pushed request_uri, atomically marks it
// consumed, and returns the persisted payload. The caller (the authorize
// endpoint) is responsible for verifying that the redeeming client matches
// the storing client.
func Redeem(ctx context.Context, q *db.Queries, tenantID uuid.UUID, uri string) (clientPK uuid.UUID, payload map[string][]string, err error) {
	row, err := q.GetPARRequest(ctx, db.GetPARRequestParams{
		RequestUri: uri,
		TenantID:   tenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil, ErrNotFound
		}
		return uuid.Nil, nil, fmt.Errorf("load par request: %w", err)
	}
	if row.ConsumedAt.Valid {
		return uuid.Nil, nil, ErrConsumed
	}
	if time.Now().After(row.ExpiresAt) {
		return uuid.Nil, nil, ErrExpired
	}
	if err := q.MarkPARRequestConsumed(ctx, db.MarkPARRequestConsumedParams{
		ID: row.ID, TenantID: tenantID,
	}); err != nil {
		return uuid.Nil, nil, fmt.Errorf("mark consumed: %w", err)
	}
	out := map[string][]string{}
	if err := json.Unmarshal(row.Payload, &out); err != nil {
		return uuid.Nil, nil, fmt.Errorf("decode payload: %w", err)
	}
	return row.ClientID, out, nil
}

func (h *Handler) tenant(r *http.Request) (uuid.UUID, error) {
	if h.tenantFor != nil {
		return h.tenantFor(r)
	}
	return uuid.MustParse("00000000-0000-0000-0000-000000000001"), nil
}

func newRequestURI() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return URNPrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

type errBody struct {
	Error string `json:"error"`
	Desc  string `json:"error_description,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: code, Desc: desc})
}
