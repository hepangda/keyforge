package csrf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	tok := Issue(w, "secret", "login")

	r := httptest.NewRequest(http.MethodPost, "/oauth/login",
		strings.NewReader(url.Values{FormField: {tok}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	if err := Validate(r, "secret", "login"); err != nil {
		t.Errorf("validate good token: %v", err)
	}
}

func TestRejectWrongFormID(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	tok := Issue(w, "secret", "login")
	r := httptest.NewRequest(http.MethodPost, "/x",
		strings.NewReader(url.Values{FormField: {tok}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	if err := Validate(r, "secret", "consent"); !errors.Is(err, ErrBadToken) {
		t.Errorf("expected bad token across formIDs, got %v", err)
	}
}

func TestRejectMissingCookie(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/x",
		strings.NewReader(url.Values{FormField: {"x"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := Validate(r, "secret", "login"); !errors.Is(err, ErrMissingToken) {
		t.Errorf("expected missing token, got %v", err)
	}
}

func TestRejectMismatchedFormVsCookie(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	cookieTok := Issue(w, "secret", "login")

	// Submit a form token that is byte-different from the cookie token,
	// even if it would be otherwise valid on its own.
	r := httptest.NewRequest(http.MethodPost, "/x",
		strings.NewReader(url.Values{FormField: {cookieTok + "x"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	if err := Validate(r, "secret", "login"); !errors.Is(err, ErrBadToken) {
		t.Errorf("expected bad token on mismatched form/cookie, got %v", err)
	}
}
