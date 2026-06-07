// Package ciba implements OpenID Connect Client-Initiated Backchannel
// Authentication (poll mode). A client POSTs to /bc-authorize with a
// login_hint identifying the user; keyforge persists a pending CIBA
// request and surfaces it to the user out-of-band (in the user portal in
// v1). The client polls /oauth/token with grant_type=
// urn:openid:params:grant-type:ciba until the user approves or denies.
package ciba

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	"github.com/hepangda/keyforge/internal/storage/users"
)

// GrantType is the OIDC CIBA token-endpoint grant_type value.
const GrantType = "urn:openid:params:grant-type:ciba"

// Errors returned by Redeem at the token endpoint.
var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
	ErrInvalidGrant         = errors.New("invalid_grant")
)

// Status values match the ciba_requests.status CHECK constraint.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusConsumed = "consumed"
)

// Handler serves POST /bc-authorize.
type Handler struct {
	q             *db.Queries
	authenticator *clientauth.Authenticator
	usersRepo     *users.Repository
	tenantFor     func(*http.Request) (uuid.UUID, error)
	ttl           time.Duration
	interval      time.Duration
}

// Config configures the Handler.
type Config struct {
	Queries       *db.Queries
	Authenticator *clientauth.Authenticator
	UsersRepo     *users.Repository
	TenantFor     func(*http.Request) (uuid.UUID, error)
	// TTL is how long the auth_req_id remains valid before turning into
	// expired_token at /oauth/token. Defaults to 10 minutes.
	TTL time.Duration
	// PollInterval is the announced interval (seconds) and the floor used
	// for slow_down enforcement.
	PollInterval time.Duration
}

// New constructs a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Queries == nil || cfg.Authenticator == nil || cfg.UsersRepo == nil {
		return nil, errors.New("ciba: incomplete config")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	return &Handler{
		q:             cfg.Queries,
		authenticator: cfg.Authenticator,
		usersRepo:     cfg.UsersRepo,
		tenantFor:     cfg.TenantFor,
		ttl:           cfg.TTL,
		interval:      cfg.PollInterval,
	}, nil
}

// Routes registers POST /bc-authorize.
func (h *Handler) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("POST /bc-authorize", h.BackchannelAuthorize)
}

// AuthorizeResponse is the JSON shape of /bc-authorize.
type AuthorizeResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// BackchannelAuthorize handles POST /bc-authorize.
func (h *Handler) BackchannelAuthorize(w http.ResponseWriter, r *http.Request) {
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

	loginHint := strings.TrimSpace(r.PostFormValue("login_hint"))
	if loginHint == "" {
		// id_token_hint / login_hint_token resolution deferred until M15.
		writeError(w, http.StatusBadRequest, "unknown_user_id",
			"login_hint is required in v1 (id_token_hint not yet supported)")
		return
	}
	user, err := h.usersRepo.GetByEmail(ctx, loginHint)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown_user_id", "")
		return
	}

	scopes := splitFields(r.PostFormValue("scope"))
	resource := r.PostForm["resource"]
	if resource == nil {
		resource = []string{}
	}
	bindingMsg := r.PostFormValue("binding_message")
	acrValues := r.PostFormValue("acr_values")

	id, err := newAuthReqID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	row, err := h.q.InsertCIBARequest(ctx, db.InsertCIBARequestParams{
		TenantID:        tid,
		ClientID:        authRes.Client.ID,
		AuthReqID:       id,
		UserID:          uuidPG(user.ID),
		BindingMessage:  textOpt(bindingMsg),
		Scopes:          scopes,
		Audience:        resource,
		AcrValues:       textOpt(acrValues),
		IntervalSeconds: int32(h.interval / time.Second), //nolint:gosec // bounded
		ExpiresAt:       time.Now().Add(h.ttl).UTC(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = writeJSONEnc(w, AuthorizeResponse{
		AuthReqID: id,
		ExpiresIn: int(time.Until(row.ExpiresAt).Seconds()),
		Interval:  int(h.interval / time.Second),
	})
}

// RedeemResult is what the token endpoint receives back from Redeem on a
// successful CIBA resolution.
type RedeemResult struct {
	ClientPK uuid.UUID
	UserID   uuid.UUID
	Scopes   []string
	Audience []string
}

// Redeem is what the token endpoint calls for grant_type=ciba. It returns
// the resolved grant once the user has approved, or one of the polling-
// error sentinels otherwise.
func Redeem(ctx context.Context, q *db.Queries, tenantID uuid.UUID, authReqID string, minInterval time.Duration) (*RedeemResult, error) {
	row, err := q.GetCIBAByAuthReqID(ctx, db.GetCIBAByAuthReqIDParams{
		AuthReqID: authReqID, TenantID: tenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidGrant
		}
		return nil, fmt.Errorf("load ciba: %w", err)
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrExpiredToken
	}
	switch row.Status {
	case StatusConsumed, StatusExpired:
		return nil, ErrInvalidGrant
	case StatusDenied:
		return nil, ErrAccessDenied
	}
	if row.LastPolledAt.Valid && time.Since(row.LastPolledAt.Time) < minInterval {
		_ = q.TouchCIBAPoll(ctx, db.TouchCIBAPollParams{ID: row.ID, TenantID: tenantID})
		return nil, ErrSlowDown
	}
	if err := q.TouchCIBAPoll(ctx, db.TouchCIBAPollParams{ID: row.ID, TenantID: tenantID}); err != nil {
		return nil, fmt.Errorf("touch ciba: %w", err)
	}
	if row.Status != StatusApproved {
		return nil, ErrAuthorizationPending
	}
	if err := q.SetCIBAStatus(ctx, db.SetCIBAStatusParams{
		ID: row.ID, TenantID: tenantID, Status: StatusConsumed,
	}); err != nil {
		return nil, fmt.Errorf("consume ciba: %w", err)
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

// Approve transitions a pending CIBA request to approved. The user portal
// (M18) wires this into the "Pending sign-in approvals" page; tests call
// it directly.
func Approve(ctx context.Context, q *db.Queries, tenantID, id uuid.UUID) error {
	return q.SetCIBAStatus(ctx, db.SetCIBAStatusParams{
		ID: id, TenantID: tenantID, Status: StatusApproved,
	})
}

// Deny transitions a pending CIBA request to denied.
func Deny(ctx context.Context, q *db.Queries, tenantID, id uuid.UUID) error {
	return q.SetCIBAStatus(ctx, db.SetCIBAStatusParams{
		ID: id, TenantID: tenantID, Status: StatusDenied,
	})
}

func (h *Handler) tenant(r *http.Request) (uuid.UUID, error) {
	if h.tenantFor != nil {
		return h.tenantFor(r)
	}
	return uuid.MustParse("00000000-0000-0000-0000-000000000001"), nil
}

func newAuthReqID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
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

func textOpt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func uuidPG(u uuid.UUID) pgtype.UUID {
	if u == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: u, Valid: true}
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = writeJSONEnc(w, struct {
		Error string `json:"error"`
		Desc  string `json:"error_description,omitempty"`
	}{Error: code, Desc: desc})
}
