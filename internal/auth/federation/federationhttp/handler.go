// Package federationhttp wires the upstream-OIDC handlers into chi:
//
//	GET  /oauth/federation/{slug}/start    — kick off the upstream flow
//	GET  /oauth/federation/{slug}/callback — finish, link/create user,
//	                                         return to /oauth/consent
//
// The auth_request that originally hit /oauth/authorize is preserved end
// to end: BuildAuthCodeRequest stores state/nonce/PKCE verifier on that
// row, and the callback looks it back up by state.
package federationhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/auth/federation"
	"github.com/hepangda/keyforge/internal/httpx"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// Handler owns the two routes. It mutates the same auth_requests row the
// authflow package created, so the post-callback redirect to /oauth/consent
// completes the original /oauth/authorize transaction.
type Handler struct {
	registry     *federation.Registry
	q            *db.Queries
	usersRepo    *users.Repository
	sessionStore session.Store
	logger       *slog.Logger
	tenantFor    func(*http.Request) (uuid.UUID, error)
	// publicBaseURL is the absolute base of this keyforge instance
	// (e.g. "https://auth.example.com"). The callback URL given to the
	// upstream IdP is built from it.
	publicBaseURL string
	sessionTTL    time.Duration
}

// New constructs a Handler.
func New(reg *federation.Registry, q *db.Queries, usersRepo *users.Repository, sessions session.Store, opt Options) *Handler {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.SessionTTL == 0 {
		opt.SessionTTL = 24 * time.Hour
	}
	return &Handler{
		registry:      reg,
		q:             q,
		usersRepo:     usersRepo,
		sessionStore:  sessions,
		logger:        opt.Logger,
		tenantFor:     opt.TenantFor,
		publicBaseURL: strings.TrimRight(opt.PublicBaseURL, "/"),
		sessionTTL:    opt.SessionTTL,
	}
}

// Options is the optional half of New.
type Options struct {
	Logger        *slog.Logger
	TenantFor     func(*http.Request) (uuid.UUID, error)
	PublicBaseURL string
	SessionTTL    time.Duration
}

// Routes registers the federation endpoints.
func (h *Handler) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("GET /oauth/federation/{slug}/start", h.Start)
	mux.HandleFunc("GET /oauth/federation/{slug}/callback", h.Callback)
}

func (h *Handler) tenant(r *http.Request) (uuid.UUID, error) {
	if h.tenantFor != nil {
		return h.tenantFor(r)
	}
	return uuid.MustParse("00000000-0000-0000-0000-000000000001"), nil
}

func (h *Handler) tenantCtx(r *http.Request) (context.Context, uuid.UUID, error) {
	tid, err := h.tenant(r)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return postgres.ContextWithTenant(r.Context(), tid), tid, nil
}

func (h *Handler) callbackURL(slug string) string {
	return h.publicBaseURL + "/oauth/federation/" + slug + "/callback"
}

// Start builds the upstream authorization URL, stamps the auth_request
// row with (state, nonce, verifier), and redirects the browser.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.Error(w, "missing slug", http.StatusBadRequest)
		return
	}
	arIDStr := r.URL.Query().Get("ar")
	arID, err := uuid.Parse(arIDStr)
	if err != nil {
		http.Error(w, "missing or invalid ar", http.StatusBadRequest)
		return
	}
	ctx, tid, err := h.tenantCtx(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conn, err := h.registry.LookupBySlug(ctx, tid, slug)
	if err != nil {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}
	req, err := h.q.GetAuthRequest(ctx, db.GetAuthRequestParams{ID: arID, TenantID: tid})
	if err != nil {
		http.Error(w, "auth request not found", http.StatusBadRequest)
		return
	}
	ac, err := conn.BuildAuthCodeRequest(ctx, h.callbackURL(slug))
	if err != nil {
		h.logger.Warn("federation build auth code", slog.Any("error", err))
		http.Error(w, "federation start failed", http.StatusBadGateway)
		return
	}
	if err := h.q.SetAuthRequestFederation(ctx, db.SetAuthRequestFederationParams{
		ID:                     req.ID,
		TenantID:               tid,
		FederationIdpID:        pgtype.UUID{Bytes: conn.ID(), Valid: true},
		FederationState:        pgtype.Text{String: ac.State, Valid: true},
		FederationNonce:        pgtype.Text{String: ac.Nonce, Valid: true},
		FederationPkceVerifier: pgtype.Text{String: ac.PKCEVerifier, Valid: true},
	}); err != nil {
		h.logger.Warn("federation stamp ar", slog.Any("error", err))
		http.Error(w, "federation stamp failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, ac.URL, http.StatusFound)
}

// Callback finishes the federation flow: exchanges the code, validates
// the id_token, links / creates a local user, opens a session, and
// redirects to /oauth/consent for the original auth_request.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			http.Error(w, "upstream error: "+errParam, http.StatusBadRequest)
			return
		}
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}
	ctx, tid, err := h.tenantCtx(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := h.q.GetAuthRequestByFederationState(ctx,
		db.GetAuthRequestByFederationStateParams{
			TenantID:        tid,
			FederationState: pgtype.Text{String: state, Valid: true},
		})
	if err != nil {
		http.Error(w, "unknown federation state", http.StatusBadRequest)
		return
	}
	if !req.FederationIdpID.Valid {
		http.Error(w, "federation idp missing", http.StatusBadRequest)
		return
	}
	conn, err := h.registry.LookupByID(ctx, tid, uuidFromPG(req.FederationIdpID))
	if err != nil {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}

	mapped, err := conn.Exchange(ctx, h.callbackURL(slug), code,
		req.FederationPkceVerifier.String, req.FederationNonce.String)
	if err != nil {
		h.logger.Warn("federation exchange", slog.Any("error", err))
		http.Error(w, "federation exchange failed", http.StatusBadGateway)
		return
	}

	user, err := h.resolveOrProvisionUser(ctx, tid, conn.ID(), mapped)
	if err != nil {
		h.logger.Warn("federation resolve user", slog.Any("error", err))
		http.Error(w, "user resolution failed", http.StatusInternalServerError)
		return
	}

	sess, err := h.sessionStore.Create(ctx, session.CreateInput{
		UserID:    user.ID,
		IP:        httpx.RealIPFromContext(r.Context()),
		UserAgent: r.UserAgent(),
		MFALevel:  "pwd",
		AMR:       []string{"pwd", "ext"},
		TTL:       h.sessionTTL,
	})
	if err != nil {
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}
	session.WriteCookie(w, sess.ID.String(), h.sessionTTL)

	if err := h.q.AttachAuthRequestSession(ctx, db.AttachAuthRequestSessionParams{
		ID:             req.ID,
		TenantID:       tid,
		LoginSessionID: pgtype.UUID{Bytes: sess.ID, Valid: true},
		UserID:         pgtype.UUID{Bytes: user.ID, Valid: true},
	}); err != nil {
		h.logger.Warn("federation attach session", slog.Any("error", err))
	}
	//nolint:gosec // ar is a server-issued uuid
	http.Redirect(w, r, "/oauth/consent?ar="+req.ID.String(), http.StatusFound)
}

// resolveOrProvisionUser maps an upstream identity to a local user. If
// the (idp, subject) pair is already linked, the linked user wins. Else,
// if the email maps to an existing user in this tenant we link to that.
// Else we provision a fresh user.
func (h *Handler) resolveOrProvisionUser(ctx context.Context, tid, idpID uuid.UUID, mapped *federation.Mapped) (*users.User, error) {
	if row, err := h.q.GetFederatedUser(ctx, db.GetFederatedUserParams{
		TenantID: tid, IdpID: idpID, Subject: mapped.Subject,
	}); err == nil {
		// Touch the link.
		_, _ = h.q.LinkFederatedIdentity(ctx, db.LinkFederatedIdentityParams{
			TenantID: tid, IdpID: idpID, UserID: row.UserID, Subject: mapped.Subject,
		})
		return h.usersRepo.GetByID(ctx, row.UserID)
	}

	if mapped.Email != "" {
		if existing, err := h.usersRepo.GetByEmail(ctx, mapped.Email); err == nil {
			if _, err := h.q.LinkFederatedIdentity(ctx, db.LinkFederatedIdentityParams{
				TenantID: tid, IdpID: idpID, UserID: existing.ID, Subject: mapped.Subject,
			}); err != nil {
				return nil, err
			}
			return existing, nil
		} else if !errors.Is(err, users.ErrNotFound) {
			return nil, err
		}
	}

	created, err := h.usersRepo.Create(ctx, users.CreateInput{
		Email:         mapped.Email,
		EmailVerified: mapped.Email != "",
		DisplayName:   mapped.DisplayName,
	})
	if err != nil {
		return nil, err
	}
	if _, err := h.q.LinkFederatedIdentity(ctx, db.LinkFederatedIdentityParams{
		TenantID: tid, IdpID: idpID, UserID: created.ID, Subject: mapped.Subject,
	}); err != nil {
		return nil, err
	}
	return created, nil
}

func uuidFromPG(p pgtype.UUID) uuid.UUID {
	if !p.Valid {
		return uuid.Nil
	}
	u, _ := uuid.FromBytes(p.Bytes[:])
	return u
}
