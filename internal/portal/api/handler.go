// Package portal implements the user-portal REST API mounted at
// /portal/api/v1/*. Every endpoint is scoped to "the caller's own
// account": never another user's, even within the same tenant.
//
// Authentication is via Bearer access token carrying the kf:portal scope
// (registered for the keyforge-spa client in M17 and minted at /oauth/token).
// The user identity is read off the bearer's user_id; nothing on the wire
// can target a different user.
package portal

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/audit"
	"github.com/hepangda/keyforge/internal/auth/authz"
	"github.com/hepangda/keyforge/internal/auth/mfa"
	"github.com/hepangda/keyforge/internal/auth/password"
	"github.com/hepangda/keyforge/internal/httpx"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// Handler bundles the portal routes.
type Handler struct {
	q            *db.Queries
	usersRepo    *users.Repository
	sessionStore session.Store
	totp         *mfa.TOTPFactor
	recovery     *mfa.RecoveryFactor
	webauthn     *mfa.WebAuthnFactor
	auditor      *audit.Recorder
	authn        *authz.Authenticator
	tenantFor    func(*http.Request) (uuid.UUID, error)
}

// Config configures the handler. MFA factors are optional; missing
// factors yield 404 on the corresponding endpoint.
type Config struct {
	Queries       *db.Queries
	UsersRepo     *users.Repository
	SessionStore  session.Store
	TOTP          *mfa.TOTPFactor
	Recovery      *mfa.RecoveryFactor
	WebAuthn      *mfa.WebAuthnFactor
	Auditor       *audit.Recorder
	Authenticator *authz.Authenticator
	TenantFor     func(*http.Request) (uuid.UUID, error)
}

// New constructs a portal Handler.
func New(cfg Config) *Handler {
	return &Handler{
		q:            cfg.Queries,
		usersRepo:    cfg.UsersRepo,
		sessionStore: cfg.SessionStore,
		totp:         cfg.TOTP,
		recovery:     cfg.Recovery,
		webauthn:     cfg.WebAuthn,
		auditor:      cfg.Auditor,
		authn:        cfg.Authenticator,
		tenantFor:    cfg.TenantFor,
	}
}

// Mount registers the portal routes under prefix on parent.
func (h *Handler) Mount(parent chi.Router, prefix string) {
	parent.Route(prefix, func(s chi.Router) {
		s.Use(h.tenancyMiddleware)
		s.Use(h.authn.ScopedMiddleware(authz.PortalScope))

		s.Get("/me", h.getMe)
		s.Patch("/me", h.patchMe)
		s.Delete("/me", h.deleteAccount)

		s.Get("/sessions", h.listSessions)
		s.Delete("/sessions/{id}", h.revokeSession)

		s.Get("/consents", h.listConsents)
		s.Delete("/consents/{id}", h.revokeConsent)

		s.Get("/mfa", h.mfaStatus)
		s.Post("/mfa/totp/enroll/begin", h.totpEnrollBegin)
		s.Post("/mfa/totp/enroll/confirm", h.totpEnrollConfirm)
		s.Delete("/mfa/totp", h.totpRemove)
		s.Post("/mfa/recovery/regenerate", h.recoveryRegenerate)
		s.Get("/mfa/webauthn", h.webauthnList)
		s.Post("/mfa/webauthn/register/begin", h.webauthnRegisterBegin)
		s.Post("/mfa/webauthn/register/finish", h.webauthnRegisterFinish)
		s.Delete("/mfa/webauthn/{id}", h.webauthnRemove)

		s.Post("/password", h.changePassword)
	})
}

func (h *Handler) tenancyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := uuid.MustParse("00000000-0000-0000-0000-000000000001")
		if h.tenantFor != nil {
			t, err := h.tenantFor(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			tid = t
		}
		next.ServeHTTP(w, r.WithContext(postgres.ContextWithTenant(r.Context(), tid)))
	})
}

func (h *Handler) caller(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	id := authz.FromContext(r.Context())
	if id == nil || id.UserID == uuid.Nil {
		http.Error(w, "user identity missing", http.StatusForbidden)
		return uuid.Nil, uuid.Nil, false
	}
	tid, err := postgres.MustTenant(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return uuid.Nil, uuid.Nil, false
	}
	return tid, id.UserID, true
}

func (h *Handler) record(r *http.Request, action, targetType, targetID string) {
	tid, _ := postgres.MustTenant(r.Context())
	id := authz.FromContext(r.Context())
	ev := audit.Event{
		TenantID:   tid,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		IP:         httpx.RealIPFromContext(r.Context()),
		UserAgent:  r.UserAgent(),
	}
	if id != nil && id.UserID != uuid.Nil {
		u := id.UserID
		ev.ActorUserID = &u
	}
	h.auditor.Record(r.Context(), ev)
}

// =====================================================================
// /me
// =====================================================================

func (h *Handler) getMe(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	_ = tid
	user, err := h.usersRepo.GetByID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"display_name":   user.DisplayName,
		"locale":         user.Locale,
		"zoneinfo":       user.Zoneinfo,
		"picture_url":    user.PictureURL,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	})
}

type patchMeReq struct {
	DisplayName *string `json:"display_name,omitempty"`
	Locale      *string `json:"locale,omitempty"`
	Zoneinfo    *string `json:"zoneinfo,omitempty"`
	PictureURL  *string `json:"picture_url,omitempty"`
}

func (h *Handler) patchMe(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	var body patchMeReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	user, err := h.usersRepo.GetByID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	displayName := pickString(body.DisplayName, user.DisplayName)
	locale := pickString(body.Locale, user.Locale)
	zoneinfo := pickString(body.Zoneinfo, user.Zoneinfo)
	pictureURL := pickString(body.PictureURL, user.PictureURL)
	updated, err := h.q.UpdateUser(r.Context(), db.UpdateUserParams{
		ID:            uid,
		TenantID:      tid,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		DisplayName:   pgText(displayName),
		Locale:        pgText(locale),
		Zoneinfo:      pgText(zoneinfo),
		PictureUrl:    pgText(pictureURL),
		Enabled:       true,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "user.update", "user", uid.String())
	writeJSON(w, map[string]any{
		"id":           updated.ID,
		"display_name": textOrEmpty(updated.DisplayName),
		"locale":       textOrEmpty(updated.Locale),
		"zoneinfo":     textOrEmpty(updated.Zoneinfo),
		"picture_url":  textOrEmpty(updated.PictureUrl),
	})
}

func pickString(override *string, fallback string) string {
	if override == nil {
		return fallback
	}
	return *override
}

func (h *Handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	if err := h.q.SoftDeleteUser(r.Context(), db.SoftDeleteUserParams{
		ID: uid, TenantID: tid,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.sessionStore.RevokeAllForUser(r.Context(), uid); err != nil {
		// non-fatal: account is already soft-deleted
		_ = err
	}
	h.record(r, "account.soft_delete", "user", uid.String())
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// /sessions
// =====================================================================

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	_, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	rows, err := h.sessionStore.ListForUser(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, s := range rows {
		out = append(out, map[string]any{
			"id":           s.ID,
			"ip":           s.IP,
			"user_agent":   s.UserAgent,
			"mfa_level":    s.MFALevel,
			"amr":          s.AMR,
			"auth_time":    s.AuthTime,
			"last_seen_at": s.LastSeenAt,
			"expires_at":   s.ExpiresAt,
		})
	}
	writeJSON(w, out)
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	_, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	// Confirm the session belongs to the caller before revoking — the
	// store.Revoke is tenant-scoped but not user-scoped, so we have to
	// look it up first.
	sess, err := h.sessionStore.Get(r.Context(), id)
	if err != nil || sess.UserID != uid {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := h.sessionStore.Revoke(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "session.revoke", "session", id.String())
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// /consents
// =====================================================================

func (h *Handler) listConsents(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	rows, err := h.q.ListUserConsents(r.Context(), db.ListUserConsentsParams{
		TenantID: tid, UserID: uid,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"id":         c.ID,
			"client_id":  c.ClientID,
			"scopes":     c.Scopes,
			"granted_at": c.GrantedAt,
		})
	}
	writeJSON(w, out)
}

func (h *Handler) revokeConsent(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	// Cross-check that the consent belongs to the caller before
	// revoking. Cheaper than a join; the LIST query is right above.
	rows, err := h.q.ListUserConsents(r.Context(), db.ListUserConsentsParams{
		TenantID: tid, UserID: uid,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var owned bool
	for _, c := range rows {
		if c.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := h.q.RevokeUserConsent(r.Context(), db.RevokeUserConsentParams{
		ID: id, TenantID: tid,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "consent.revoke", "consent", id.String())
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// /mfa
// =====================================================================

func (h *Handler) mfaStatus(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	totp, webauthn, remaining := false, false, int64(0)
	if h.totp != nil {
		totp, _ = h.totp.IsEnrolled(r.Context(), tid, uid)
	}
	if h.webauthn != nil {
		webauthn, _ = h.webauthn.IsEnrolled(r.Context(), tid, uid)
	}
	if h.recovery != nil {
		remaining, _ = h.recovery.Remaining(r.Context(), tid, uid)
	}
	writeJSON(w, map[string]any{
		"totp":                     totp,
		"webauthn":                 webauthn,
		"recovery_codes_remaining": remaining,
	})
}

func (h *Handler) totpEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if h.totp == nil {
		http.Error(w, "totp not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	user, err := h.usersRepo.GetByID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	res, err := h.totp.BeginEnroll(r.Context(), tid, uid, user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "mfa.totp.enroll.begin", "user", uid.String())
	writeJSON(w, map[string]any{
		"otpauth_url": res.OTPAuthURL,
		"secret":      res.Secret,
	})
}

type totpConfirmReq struct {
	Code string `json:"code"`
}

func (h *Handler) totpEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	if h.totp == nil {
		http.Error(w, "totp not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	var body totpConfirmReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := h.totp.ConfirmEnroll(r.Context(), tid, uid, body.Code); err != nil {
		if errors.Is(err, mfa.ErrTOTPNotVerified) {
			http.Error(w, "code did not verify", http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "mfa.totp.enroll.confirm", "user", uid.String())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) totpRemove(w http.ResponseWriter, r *http.Request) {
	if h.totp == nil {
		http.Error(w, "totp not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	if err := h.totp.Remove(r.Context(), tid, uid); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "mfa.totp.remove", "user", uid.String())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) recoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	if h.recovery == nil {
		http.Error(w, "recovery codes not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	codes, err := h.recovery.Generate(r.Context(), tid, uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "mfa.recovery.regenerate", "user", uid.String())
	writeJSON(w, map[string]any{"codes": codes})
}

// =====================================================================
// /password
// =====================================================================

type changePasswordReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	var body changePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if len(body.New) < 8 {
		http.Error(w, "new password too short", http.StatusBadRequest)
		return
	}
	cred, err := h.q.GetUserCredentials(r.Context(), db.GetUserCredentialsParams{
		UserID: uid, TenantID: tid,
	})
	if err != nil {
		http.Error(w, "credentials missing", http.StatusBadRequest)
		return
	}
	if err := password.Verify(cred.PasswordHash, body.Current); err != nil {
		http.Error(w, "current password incorrect", http.StatusBadRequest)
		return
	}
	hash, err := password.Hash(body.New, password.DefaultParams())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.q.UpsertUserCredentials(r.Context(), db.UpsertUserCredentialsParams{
		UserID:       uid,
		TenantID:     tid,
		PasswordHash: hash,
		Algorithm:    "argon2id",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "user.password_change", "user", uid.String())
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func pgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func textOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
