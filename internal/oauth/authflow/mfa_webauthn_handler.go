package authflow

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/auth/mfa"
	"github.com/hepangda/keyforge/internal/httpx/csrf"
)

// mfaWebAuthnPageData backs the JS-driven assertion page.
type mfaWebAuthnPageData struct {
	Title         string
	Tenant        struct{ DisplayName string }
	AuthRequestID string
	CSRFToken     string
	OtherFactors  []mfaLink
}

// webauthnBeginResponse mirrors the structure returned by the portal's
// register/begin endpoint so the same SPA helpers can drive both
// ceremonies.
type webauthnBeginResponse struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	PublicKey   any       `json:"publicKey"`
}

type webauthnFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

// MFAWebAuthnGET renders the WebAuthn step-up page. The page itself is
// tiny — its <script> drives navigator.credentials.get() against the
// JSON endpoints below.
func (h *Handler) MFAWebAuthnGET(w http.ResponseWriter, r *http.Request) {
	arID, ok := h.lookupAuthRequest(w, r)
	if !ok {
		return
	}
	if h.mfaFactors.WebAuthn == nil {
		h.renderError(w, r, http.StatusNotFound, "WebAuthn not enabled", "")
		return
	}
	data := mfaWebAuthnPageData{
		Title:         "Use your passkey",
		AuthRequestID: arID.String(),
		CSRFToken:     csrf.Issue(w, arID.String(), "mfa-webauthn"),
		OtherFactors:  h.otherFactorLinks(r.Context(), arID, "webauthn"),
	}
	data.Tenant.DisplayName = "keyforge"
	h.render(w, r, "mfa_webauthn.html", data)
}

// MFAWebAuthnBegin starts an assertion ceremony for the session-bound
// user and returns the CredentialAssertion options for the browser.
func (h *Handler) MFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	if h.mfaFactors.WebAuthn == nil {
		http.Error(w, "webauthn not enabled", http.StatusNotFound)
		return
	}
	arID, err := uuid.Parse(r.URL.Query().Get("ar"))
	if err != nil {
		http.Error(w, "missing ar", http.StatusBadRequest)
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userID, ok := h.requireAuthedUser(ctx, w, r, tid, arID)
	if !ok {
		return
	}
	user, err := h.usersRepo.GetByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Email
	}
	options, chID, err := h.mfaFactors.WebAuthn.LoginBegin(ctx, tid, userID, user.Email, displayName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, webauthnBeginResponse{
		ChallengeID: chID,
		PublicKey:   options.Response,
	})
}

// MFAWebAuthnFinish consumes the assertion response, upgrades the
// session's mfa_level/amr, and returns a redirect URL.
func (h *Handler) MFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	if h.mfaFactors.WebAuthn == nil {
		http.Error(w, "webauthn not enabled", http.StatusNotFound)
		return
	}
	arID, err := uuid.Parse(r.URL.Query().Get("ar"))
	if err != nil {
		http.Error(w, "missing ar", http.StatusBadRequest)
		return
	}
	if err := validateCSRFFromHeader(r); err != nil {
		http.Error(w, "csrf invalid", http.StatusForbidden)
		return
	}
	var body webauthnFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	chID, err := uuid.Parse(body.ChallengeID)
	if err != nil {
		http.Error(w, "bad challenge_id", http.StatusBadRequest)
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userID, ok := h.requireAuthedUser(ctx, w, r, tid, arID)
	if !ok {
		return
	}
	user, err := h.usersRepo.GetByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Email
	}

	// LoginFinish reads the assertion off http.Request.Body; wrap our
	// JSON body's `credential` field as the inner request body.
	inner := r.Clone(ctx)
	inner.Body = io.NopCloser(bytes.NewReader(body.Credential))
	inner.ContentLength = int64(len(body.Credential))
	inner.Header.Set("Content-Type", "application/json")

	if err := h.mfaFactors.WebAuthn.LoginFinish(ctx, tid, userID,
		user.Email, displayName, chID, inner); err != nil {
		if _, isFinishErr := err.(interface{ Unwrap() error }); isFinishErr || err == mfa.ErrWebAuthnChallengeGone {
			http.Error(w, "assertion failed", http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.upgradeSessionAndContinue(w, r, ctx, tid, arID, "webauthn", []string{"pwd", "mfa", "webauthn"})
}

// writeJSON is a tiny helper to keep the WebAuthn handlers terse. It
// mirrors what the portal package uses; duplicated here so authflow has
// no dependency on internal/portal.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// validateCSRFFromHeader runs the same double-submit comparison
// csrf.Validate performs, except the presented value comes off the
// X-CSRF-Token header so the SPA can POST a JSON body. The cookie is
// already HMAC-bound to (secret, formID) by csrf.Issue.
func validateCSRFFromHeader(r *http.Request) error {
	cookie, err := r.Cookie(csrf.CookieName)
	if err != nil || cookie.Value == "" {
		return csrf.ErrMissingToken
	}
	hdr := r.Header.Get("X-CSRF-Token")
	if hdr == "" {
		return csrf.ErrMissingToken
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(hdr)) != 1 {
		return csrf.ErrBadToken
	}
	return nil
}
