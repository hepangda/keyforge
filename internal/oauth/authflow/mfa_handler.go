package authflow

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/auth/mfa"
	"github.com/hepangda/keyforge/internal/httpx/csrf"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// MFAFactors is the set of MFA factor wrappers wired into the login flow.
// All three are optional; if a factor is nil, the corresponding routes will
// short-circuit with "not available" error pages.
type MFAFactors struct {
	TOTP     *mfa.TOTPFactor
	WebAuthn *mfa.WebAuthnFactor
	Recovery *mfa.RecoveryFactor
}

// IsConfigured reports whether at least one factor is available.
func (m MFAFactors) IsConfigured() bool {
	return m.TOTP != nil || m.WebAuthn != nil || m.Recovery != nil
}

// SetMFAFactors attaches the factor wrappers to the handler. Optional —
// if never called, MFA endpoints behave as if no factor is enrolled and
// /oauth/login proceeds straight to consent.
func (h *Handler) SetMFAFactors(f MFAFactors) { h.mfaFactors = f }

// MountMFA registers the /oauth/mfa/* routes alongside the core auth
// endpoints. Call after Routes(mux).
func (h *Handler) MountMFA(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("GET /oauth/mfa", h.MFAChooseGET)
	mux.HandleFunc("GET /oauth/mfa/totp", h.MFATOTPGET)
	mux.HandleFunc("POST /oauth/mfa/totp", h.MFATOTPPOST)
	mux.HandleFunc("GET /oauth/mfa/recovery", h.MFARecoveryGET)
	mux.HandleFunc("POST /oauth/mfa/recovery", h.MFARecoveryPOST)
	mux.HandleFunc("GET /oauth/mfa/webauthn", h.MFAWebAuthnGET)
	mux.HandleFunc("POST /oauth/mfa/webauthn/begin", h.MFAWebAuthnBegin)
	mux.HandleFunc("POST /oauth/mfa/webauthn/finish", h.MFAWebAuthnFinish)
}

// mfaSelectionPageData backs the chooser screen rendered when more than
// one factor type is available to the user.
type mfaSelectionPageData struct {
	Title         string
	Tenant        struct{ DisplayName string }
	AuthRequestID string
	HasTOTP       bool
	HasWebAuthn   bool
	HasRecovery   bool
}

type mfaFormPageData struct {
	Title         string
	Tenant        struct{ DisplayName string }
	AuthRequestID string
	CSRFToken     string
	Action        string // POST endpoint
	InputLabel    string
	InputName     string
	InputType     string // "text" | "password"
	HelpText      string
	Error         string
	OtherFactors  []mfaLink
}

type mfaLink struct {
	Label string
	HREF  string
}

// stepUpRequired returns the destination path under /oauth/mfa/* that the
// user should land on after entering credentials. Returns "" if no
// step-up is required (no enrolled factor) and consent can proceed.
func (h *Handler) stepUpRequired(ctx context.Context, tenantID, userID, arID uuid.UUID) (string, error) {
	if !h.mfaFactors.IsConfigured() {
		return "", nil
	}
	var totpOK, webOK bool
	if h.mfaFactors.TOTP != nil {
		ok, err := h.mfaFactors.TOTP.IsEnrolled(ctx, tenantID, userID)
		if err != nil {
			return "", err
		}
		totpOK = ok
	}
	if h.mfaFactors.WebAuthn != nil {
		ok, err := h.mfaFactors.WebAuthn.IsEnrolled(ctx, tenantID, userID)
		if err != nil {
			return "", err
		}
		webOK = ok
	}
	switch {
	case totpOK && webOK:
		return "/oauth/mfa?ar=" + arID.String(), nil
	case totpOK:
		return "/oauth/mfa/totp?ar=" + arID.String(), nil
	case webOK:
		// WebAuthn ceremonies require JS; the chooser page hosts the JS so
		// we route through it even for a single factor.
		return "/oauth/mfa?ar=" + arID.String(), nil
	}
	return "", nil
}

// MFAChooseGET renders a screen letting the user pick a factor when more
// than one is available. Recovery-code entry is always offered as a link.
func (h *Handler) MFAChooseGET(w http.ResponseWriter, r *http.Request) {
	arID, ok := h.lookupAuthRequest(w, r)
	if !ok {
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}
	userID, ok := h.requireAuthedUser(ctx, w, r, tid, arID)
	if !ok {
		return
	}
	data := mfaSelectionPageData{Title: "Verify it's you", AuthRequestID: arID.String()}
	data.Tenant.DisplayName = "keyforge"
	if h.mfaFactors.TOTP != nil {
		ok, _ := h.mfaFactors.TOTP.IsEnrolled(ctx, tid, userID)
		data.HasTOTP = ok
	}
	if h.mfaFactors.WebAuthn != nil {
		ok, _ := h.mfaFactors.WebAuthn.IsEnrolled(ctx, tid, userID)
		data.HasWebAuthn = ok
	}
	if h.mfaFactors.Recovery != nil {
		n, _ := h.mfaFactors.Recovery.Remaining(ctx, tid, userID)
		data.HasRecovery = n > 0
	}
	h.render(w, r, "mfa_choose.html", data)
}

// MFATOTPGET renders the TOTP step-up form.
func (h *Handler) MFATOTPGET(w http.ResponseWriter, r *http.Request) {
	arID, ok := h.lookupAuthRequest(w, r)
	if !ok {
		return
	}
	if h.mfaFactors.TOTP == nil {
		h.renderError(w, r, http.StatusNotFound, "TOTP not enabled", "")
		return
	}
	h.renderMFAForm(w, r, mfaFormPageData{
		Title:         "Enter your code",
		AuthRequestID: arID.String(),
		CSRFToken:     csrf.Issue(w, arID.String(), "mfa-totp"),
		Action:        "/oauth/mfa/totp",
		InputLabel:    "Six-digit code from your authenticator app",
		InputName:     "code",
		InputType:     "text",
		HelpText:      "Open your authenticator app and enter the current code.",
		OtherFactors:  h.otherFactorLinks(r.Context(), arID, "totp"),
	})
}

// MFATOTPPOST verifies the code and upgrades the session.
func (h *Handler) MFATOTPPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Bad request", "")
		return
	}
	arID, err := uuid.Parse(r.PostFormValue("auth_request_id"))
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid request", "")
		return
	}
	if err := csrf.Validate(r, arID.String(), "mfa-totp"); err != nil {
		h.renderError(w, r, http.StatusForbidden, "Session expired", "Please try again.")
		return
	}
	if h.mfaFactors.TOTP == nil {
		h.renderError(w, r, http.StatusNotFound, "TOTP not enabled", "")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}
	userID, ok := h.requireAuthedUser(ctx, w, r, tid, arID)
	if !ok {
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	if err := h.mfaFactors.TOTP.Verify(ctx, tid, userID, code); err != nil {
		h.renderMFAFormError(w, r, arID, "totp", "/oauth/mfa/totp", "code", "text",
			"That code is not correct. Try again.")
		return
	}
	h.upgradeSessionAndContinue(w, r, ctx, tid, arID, "otp", []string{"pwd", "mfa", "otp"})
}

// MFARecoveryGET renders the recovery-code form.
func (h *Handler) MFARecoveryGET(w http.ResponseWriter, r *http.Request) {
	arID, ok := h.lookupAuthRequest(w, r)
	if !ok {
		return
	}
	if h.mfaFactors.Recovery == nil {
		h.renderError(w, r, http.StatusNotFound, "Recovery codes not enabled", "")
		return
	}
	h.renderMFAForm(w, r, mfaFormPageData{
		Title:         "Enter a recovery code",
		AuthRequestID: arID.String(),
		CSRFToken:     csrf.Issue(w, arID.String(), "mfa-recovery"),
		Action:        "/oauth/mfa/recovery",
		InputLabel:    "Recovery code",
		InputName:     "code",
		InputType:     "text",
		HelpText:      "Each code works once. Enter it with or without the dash.",
		OtherFactors:  h.otherFactorLinks(r.Context(), arID, "recovery"),
	})
}

// MFARecoveryPOST consumes a recovery code and upgrades the session.
func (h *Handler) MFARecoveryPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Bad request", "")
		return
	}
	arID, err := uuid.Parse(r.PostFormValue("auth_request_id"))
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid request", "")
		return
	}
	if err := csrf.Validate(r, arID.String(), "mfa-recovery"); err != nil {
		h.renderError(w, r, http.StatusForbidden, "Session expired", "Please try again.")
		return
	}
	if h.mfaFactors.Recovery == nil {
		h.renderError(w, r, http.StatusNotFound, "Recovery codes not enabled", "")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}
	userID, ok := h.requireAuthedUser(ctx, w, r, tid, arID)
	if !ok {
		return
	}
	code := r.PostFormValue("code")
	if err := h.mfaFactors.Recovery.Verify(ctx, tid, userID, code); err != nil {
		if errors.Is(err, mfa.ErrRecoveryNotFound) || errors.Is(err, mfa.ErrRecoveryConsumed) {
			h.renderMFAFormError(w, r, arID, "recovery", "/oauth/mfa/recovery", "code", "text",
				"That recovery code is not valid.")
			return
		}
		h.renderError(w, r, http.StatusInternalServerError, "Recovery code check failed", err.Error())
		return
	}
	h.upgradeSessionAndContinue(w, r, ctx, tid, arID, "recovery", []string{"pwd", "mfa", "rba"})
}

// requireAuthedUser resolves the session-bound user for the auth request
// or renders an error / redirects to login.
func (h *Handler) requireAuthedUser(ctx context.Context, w http.ResponseWriter, r *http.Request, tid, arID uuid.UUID) (uuid.UUID, bool) {
	req, err := h.q.GetAuthRequest(ctx, db.GetAuthRequestParams{ID: arID, TenantID: tid})
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Authorization expired", "")
		return uuid.Nil, false
	}
	if !req.UserID.Valid {
		//nolint:gosec // ar is a server-issued uuid
		http.Redirect(w, r, "/oauth/login?ar="+arID.String(), http.StatusFound)
		return uuid.Nil, false
	}
	return uuidFromPG(req.UserID), true
}

// upgradeSessionAndContinue bumps the session's mfa_level/amr and
// redirects to the consent endpoint.
func (h *Handler) upgradeSessionAndContinue(w http.ResponseWriter, r *http.Request, ctx context.Context, tid, arID uuid.UUID, level string, amr []string) {
	sid, ok := session.ReadCookie(r)
	if !ok {
		//nolint:gosec // ar is a server-issued uuid
		http.Redirect(w, r, "/oauth/login?ar="+arID.String(), http.StatusFound)
		return
	}
	if err := h.sessionStore.UpgradeMFA(ctx, sid, level, amr); err != nil {
		h.logger.Warn("upgrade session mfa", slog.Any("error", err))
		h.renderError(w, r, http.StatusInternalServerError, "Session upgrade failed", err.Error())
		return
	}
	_ = tid
	//nolint:gosec // ar is a server-issued uuid
	http.Redirect(w, r, "/oauth/consent?ar="+arID.String(), http.StatusFound)
}

// renderMFAForm renders mfa_form.html with the given data.
func (h *Handler) renderMFAForm(w http.ResponseWriter, r *http.Request, data mfaFormPageData) {
	data.Tenant.DisplayName = "keyforge"
	h.render(w, r, "mfa_form.html", data)
}

func (h *Handler) renderMFAFormError(w http.ResponseWriter, r *http.Request, arID uuid.UUID, kind, action, name, inputType, msg string) {
	h.renderMFAForm(w, r, mfaFormPageData{
		Title:         "Verify it's you",
		AuthRequestID: arID.String(),
		CSRFToken:     csrf.Issue(w, arID.String(), "mfa-"+kind),
		Action:        action,
		InputLabel:    "Code",
		InputName:     name,
		InputType:     inputType,
		Error:         msg,
		OtherFactors:  h.otherFactorLinks(r.Context(), arID, kind),
	})
}

// otherFactorLinks returns links to the alternate factors a user might
// want to switch to. Recovery is always available as a fallback if
// configured; the current factor is omitted.
func (h *Handler) otherFactorLinks(_ context.Context, arID uuid.UUID, current string) []mfaLink {
	out := []mfaLink{}
	if h.mfaFactors.TOTP != nil && current != "totp" {
		out = append(out, mfaLink{Label: "Use authenticator app", HREF: "/oauth/mfa/totp?ar=" + arID.String()})
	}
	if h.mfaFactors.Recovery != nil && current != "recovery" {
		out = append(out, mfaLink{Label: "Use a recovery code", HREF: "/oauth/mfa/recovery?ar=" + arID.String()})
	}
	return out
}
