// Package csrf provides double-submit-cookie CSRF protection for
// keyforge's server-rendered login and consent forms.
//
// The session row already carries a per-session csrf_secret. On each form
// render, we emit an HMAC of (sid, formID, exp) as a hidden input AND set
// it as a separate cookie. On submit, both must arrive and match — defeats
// cross-origin POSTs which cannot read the cookie.
package csrf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Errors surfaced by this package.
var (
	ErrMissingToken = errors.New("csrf: missing token")
	ErrBadToken     = errors.New("csrf: token invalid or expired")
)

// CookieName is the CSRF cookie name. Like the session cookie, the
// `__Host-` prefix locks it to the issuing host + Path=/ + Secure.
const CookieName = "__Host-kf_csrf"

// FormField is the form field name for the matching token.
const FormField = "csrf_token"

// TokenTTL bounds how long a minted token is honoured.
const TokenTTL = 30 * time.Minute

// Issue mints a token bound to (secret, formID) with the given TTL,
// writes it as a cookie, and returns the value so the caller can also
// embed it as a hidden form field.
func Issue(w http.ResponseWriter, secret, formID string) string {
	tok := Mint(secret, formID, TokenTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(TokenTTL.Seconds()),
	})
	return tok
}

// Mint produces a token of the form "<unix-expires>.<hmac>" base64url-encoded.
func Mint(secret, formID string, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	mac := computeMAC(secret, formID, exp)
	payload := fmt.Sprintf("%d.%s", exp, base64.RawURLEncoding.EncodeToString(mac))
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

// Validate compares the cookie and form values. They must be equal AND
// the embedded HMAC must verify against (secret, formID) AND the
// expiration must be in the future.
func Validate(r *http.Request, secret, formID string) error {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return ErrMissingToken
	}
	formVal := r.PostFormValue(FormField)
	if formVal == "" {
		return ErrMissingToken
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formVal)) != 1 {
		return ErrBadToken
	}
	if err := verifyToken(cookie.Value, secret, formID); err != nil {
		return err
	}
	return nil
}

func verifyToken(token, secret, formID string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrBadToken
	}
	parts := strings.SplitN(string(raw), ".", 2)
	if len(parts) != 2 {
		return ErrBadToken
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return ErrBadToken
	}
	if time.Unix(exp, 0).Before(time.Now()) {
		return ErrBadToken
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrBadToken
	}
	want := computeMAC(secret, formID, exp)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBadToken
	}
	return nil
}

func computeMAC(secret, formID string, exp int64) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(h, "%s|%d", formID, exp)
	return h.Sum(nil)
}
