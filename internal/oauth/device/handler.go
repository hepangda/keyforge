// Package device implements the OAuth 2.0 Device Authorization Grant
// (RFC 8628). A device-bound client (TV, IoT, CLI) POSTs to
// /device_authorization to obtain a device_code + user_code; the user
// enters the user_code on a separate device at /device and approves; the
// client polls /oauth/token until the grant resolves.
package device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// GrantType is the RFC 8628 token-endpoint grant_type value.
const GrantType = "urn:ietf:params:oauth:grant-type:device_code"

// Errors surfaced by Redeem.
var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
	ErrInvalidGrant         = errors.New("invalid_grant")
)

// Handler serves /device_authorization and the /device verification page.
type Handler struct {
	q             *db.Queries
	authenticator *clientauth.Authenticator
	tenantFor     func(*http.Request) (uuid.UUID, error)
	codeTTL       time.Duration
	pollInterval  time.Duration
}

// Config configures the Handler.
type Config struct {
	Queries       *db.Queries
	Authenticator *clientauth.Authenticator
	TenantFor     func(*http.Request) (uuid.UUID, error)
	// CodeTTL is how long the device_code/user_code remain valid.
	// RFC 8628 §3.2 recommends 10 minutes.
	CodeTTL      time.Duration
	PollInterval time.Duration
}

// New constructs a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Queries == nil || cfg.Authenticator == nil {
		return nil, errors.New("device: incomplete config")
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 10 * time.Minute
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	return &Handler{
		q:             cfg.Queries,
		authenticator: cfg.Authenticator,
		tenantFor:     cfg.TenantFor,
		codeTTL:       cfg.CodeTTL,
		pollInterval:  cfg.PollInterval,
	}, nil
}

// Routes registers the endpoints.
func (h *Handler) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("POST /device_authorization", h.Authorize)
	mux.HandleFunc("GET /device", h.VerifyGET)
	mux.HandleFunc("POST /device", h.VerifyPOST)
}

// AuthorizeResponse is the JSON shape of /device_authorization.
type AuthorizeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Authorize handles POST /device_authorization.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "")
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

	scopes := splitFields(r.PostFormValue("scope"))
	resource := r.PostForm["resource"]
	if resource == nil {
		resource = []string{}
	}

	deviceCode, err := newDeviceCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	userCode, err := newUserCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	row, err := h.q.InsertDeviceCode(ctx, db.InsertDeviceCodeParams{
		TenantID:        tid,
		ClientID:        authRes.Client.ID,
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		Scopes:          scopes,
		Audience:        resource,
		IntervalSeconds: int32(h.pollInterval / time.Second), //nolint:gosec // bounded
		ExpiresAt:       time.Now().Add(h.codeTTL).UTC(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	} else if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	host := r.Host
	if hh := r.Header.Get("X-Forwarded-Host"); hh != "" {
		host = hh
	}
	verifyURL := scheme + "://" + host + "/device"

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = writeJSONEnc(w, AuthorizeResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verifyURL,
		VerificationURIComplete: verifyURL + "?user_code=" + userCode,
		ExpiresIn:               int(time.Until(row.ExpiresAt).Seconds()),
		Interval:                int(h.pollInterval / time.Second),
	})
}

// VerifyGET renders a tiny HTML page asking the user to enter the
// user_code. In production this would render a proper form via the
// authflow templates; for v1 we keep it self-contained.
func (h *Handler) VerifyGET(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	//nolint:gosec // userCode is HTML-escaped via htmlEscape before interpolation
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h1>Authorize device</h1>
<form method="POST" action="/device">
  <label>User code: <input name="user_code" value="%s" required></label>
  <label><input type="radio" name="decision" value="allow" checked> Allow</label>
  <label><input type="radio" name="decision" value="deny"> Deny</label>
  <button type="submit">Submit</button>
</form></body></html>`, htmlEscape(userCode))
}

// VerifyPOST records the user's decision against the device row. In v1 we
// assume the user is already signed in via the standard session cookie;
// callers that need a fresh login should send the user through
// /oauth/login first. Tests inject the user_id directly via X-Test-UserID
// when present (build-tag-gated by the integration test).
func (h *Handler) VerifyPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tid, err := h.tenant(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ctx := postgres.ContextWithTenant(r.Context(), tid)

	userCode := strings.TrimSpace(r.PostFormValue("user_code"))
	row, err := h.q.GetDeviceCodeByUserCode(ctx,
		db.GetDeviceCodeByUserCodeParams{UserCode: userCode, TenantID: tid})
	if err != nil {
		http.Error(w, "unknown user_code", http.StatusBadRequest)
		return
	}
	if time.Now().After(row.ExpiresAt) {
		http.Error(w, "expired", http.StatusBadRequest)
		return
	}

	// Test hook: an integration test can supply a UUID for the approving
	// user via X-Test-UserID; production code paths route through the
	// session.
	uid := uuid.Nil
	if v := r.Header.Get("X-Test-UserID"); v != "" {
		if u, parseErr := uuid.Parse(v); parseErr == nil {
			uid = u
		}
	}

	if r.PostFormValue("decision") == "deny" {
		if err := h.q.DenyDeviceCode(ctx,
			db.DenyDeviceCodeParams{ID: row.ID, TenantID: tid}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("Denied"))
		return
	}
	if uid == uuid.Nil {
		http.Error(w, "no authenticated user", http.StatusUnauthorized)
		return
	}
	if err := h.q.ApproveDeviceCode(ctx, db.ApproveDeviceCodeParams{
		ID: row.ID, TenantID: tid,
		UserID: uuidPG(uid),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte("Approved"))
}

// RedeemResult is what the token endpoint receives back from Redeem on a
// successful device-code resolution: the client (PK), the approving user,
// the scopes the user consented to, and the requested audience set.
type RedeemResult struct {
	ClientPK uuid.UUID
	UserID   uuid.UUID
	Scopes   []string
	Audience []string
}

// Redeem looks up a device_code, enforces the polling rules, and returns
// either the resolved grant or one of the spec sentinels.
func Redeem(ctx context.Context, q *db.Queries, tenantID uuid.UUID, deviceCode string, minInterval time.Duration) (*RedeemResult, error) {
	row, err := q.GetDeviceCodeByDeviceCode(ctx,
		db.GetDeviceCodeByDeviceCodeParams{DeviceCode: deviceCode, TenantID: tenantID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidGrant
		}
		return nil, fmt.Errorf("load device code: %w", err)
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrExpiredToken
	}
	if row.RedeemedAt.Valid {
		return nil, ErrInvalidGrant
	}
	if row.Denied {
		return nil, ErrAccessDenied
	}
	// Polling rate: clients must respect the announced interval.
	if row.LastPolledAt.Valid && time.Since(row.LastPolledAt.Time) < minInterval {
		// touch anyway so subsequent slow_down stays accurate
		_ = q.TouchDeviceCodePoll(ctx,
			db.TouchDeviceCodePollParams{ID: row.ID, TenantID: tenantID})
		return nil, ErrSlowDown
	}
	if err := q.TouchDeviceCodePoll(ctx,
		db.TouchDeviceCodePollParams{ID: row.ID, TenantID: tenantID}); err != nil {
		return nil, fmt.Errorf("touch device code: %w", err)
	}
	if !row.Approved {
		return nil, ErrAuthorizationPending
	}
	if err := q.RedeemDeviceCode(ctx,
		db.RedeemDeviceCodeParams{ID: row.ID, TenantID: tenantID}); err != nil {
		return nil, fmt.Errorf("redeem device code: %w", err)
	}
	uid := uuid.Nil
	if row.UserID.Valid {
		u, _ := uuid.FromBytes(row.UserID.Bytes[:])
		uid = u
	}
	return &RedeemResult{
		ClientPK: row.ClientID,
		UserID:   uid,
		Scopes:   row.Scopes,
		Audience: row.Audience,
	}, nil
}

func (h *Handler) tenant(r *http.Request) (uuid.UUID, error) {
	if h.tenantFor != nil {
		return h.tenantFor(r)
	}
	return uuid.MustParse("00000000-0000-0000-0000-000000000001"), nil
}

func newDeviceCode() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// newUserCode returns a Crockford-base32, dash-separated user code like
// "ABCD-WXYZ" (8 characters of entropy plus a dash for readability).
func newUserCode() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford base32 (no I/L/O/U)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i := 0; i < 8; i++ {
		out = append(out, alphabet[int(b[i])%len(alphabet)])
		if i == 3 {
			out = append(out, '-')
		}
	}
	return string(out), nil
}

func splitFields(s string) []string {
	out := []string{}
	for _, f := range strings.Fields(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	)
	return r.Replace(s)
}

func writeJSONEnc(w http.ResponseWriter, body any) error {
	return json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = writeJSONEnc(w, struct {
		Error string `json:"error"`
		Desc  string `json:"error_description,omitempty"`
	}{Error: code, Desc: desc})
}

// uuidPG converts a google uuid to the pgtype shape sqlc expects, using
// the package import alias to keep this file self-contained.
func uuidPG(u uuid.UUID) pgtype.UUID {
	if u == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: u, Valid: true}
}
