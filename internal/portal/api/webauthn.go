package portal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// webauthnList returns the caller's registered passkeys (metadata only,
// never the raw public-key bytes).
func (h *Handler) webauthnList(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "webauthn not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	rows, err := h.q.ListWebAuthnCredentialsForUser(r.Context(),
		db.ListWebAuthnCredentialsForUserParams{TenantID: tid, UserID: uid})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"id":           c.ID,
			"nickname":     textOrEmpty(c.Nickname),
			"transports":   c.Transports,
			"created_at":   c.CreatedAt,
			"last_used_at": c.LastUsedAt.Time,
		})
	}
	writeJSON(w, out)
}

// webauthnRegisterBegin starts a registration ceremony. The response
// carries the raw CredentialCreation options go-webauthn produces plus
// a challenge_id the SPA echoes back on /finish.
func (h *Handler) webauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "webauthn not enabled", http.StatusNotFound)
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
	options, chID, err := h.webauthn.RegisterBegin(r.Context(), tid, uid,
		user.Email, displayNameOrEmail(user.DisplayName, user.Email))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "mfa.webauthn.register.begin", "user", uid.String())
	writeJSON(w, map[string]any{
		"challenge_id": chID,
		"publicKey":    options.Response,
	})
}

type webauthnRegisterFinishReq struct {
	ChallengeID string          `json:"challenge_id"`
	Nickname    string          `json:"nickname"`
	Credential  json.RawMessage `json:"credential"`
}

// webauthnRegisterFinish consumes the browser's attestation response
// and persists the credential.
func (h *Handler) webauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "webauthn not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	var body webauthnRegisterFinishReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	chID, err := uuid.Parse(body.ChallengeID)
	if err != nil {
		http.Error(w, "bad challenge_id", http.StatusBadRequest)
		return
	}
	user, err := h.usersRepo.GetByID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// go-webauthn's FinishRegistration reads the attestation off
	// http.Request.Body; we synthesise an inner request whose body is
	// just the `credential` field from our JSON envelope.
	inner := r.Clone(r.Context())
	inner.Body = io.NopCloser(bytes.NewReader(body.Credential))
	inner.ContentLength = int64(len(body.Credential))
	inner.Header.Set("Content-Type", "application/json")

	if _, err := h.webauthn.RegisterFinish(r.Context(), tid, uid,
		user.Email, displayNameOrEmail(user.DisplayName, user.Email),
		chID, body.Nickname, inner); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.record(r, "mfa.webauthn.register.finish", "user", uid.String())
	w.WriteHeader(http.StatusNoContent)
}

// webauthnRemove deletes one of the caller's registered passkeys.
func (h *Handler) webauthnRemove(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "webauthn not enabled", http.StatusNotFound)
		return
	}
	tid, uid, ok := h.caller(w, r)
	if !ok {
		return
	}
	credID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	// Cross-check ownership before delete so users can't enumerate or
	// remove other tenants' credential rows by guessing UUIDs.
	rows, err := h.q.ListWebAuthnCredentialsForUser(r.Context(),
		db.ListWebAuthnCredentialsForUserParams{TenantID: tid, UserID: uid})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var owned bool
	for _, c := range rows {
		if c.ID == credID {
			owned = true
			break
		}
	}
	if !owned {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := h.webauthn.Remove(r.Context(), tid, credID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.record(r, "mfa.webauthn.remove", "user", uid.String())
	w.WriteHeader(http.StatusNoContent)
}

// displayNameOrEmail picks the WebAuthn display name. The spec wants
// something human-friendly but non-identifying; empty is invalid so we
// fall back to the email's local part.
func displayNameOrEmail(displayName, email string) string {
	if displayName != "" {
		return displayName
	}
	return email
}
