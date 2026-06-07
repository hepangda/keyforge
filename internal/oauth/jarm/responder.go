// Package jarm implements JWT-Secured Authorization Response Mode.
//
// JARM wraps the authorization response payload (code, state, error, etc.)
// in a signed JWT and returns it via one of four transports:
//
//   - jwt           → query string ?response=<jwt> (the default)
//   - query.jwt     → explicit query-string variant
//   - fragment.jwt  → URL fragment #response=<jwt>
//   - form_post.jwt → HTML form auto-POSTing the response field
//
// The signing key comes from the same jwks.Signer that mints ID tokens.
package jarm

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/jwks"
)

// ResponseMode names the supported JARM transports.
type ResponseMode string

// Supported response modes.
const (
	ModeJWT         ResponseMode = "jwt"
	ModeQueryJWT    ResponseMode = "query.jwt"
	ModeFragmentJWT ResponseMode = "fragment.jwt"
	ModeFormPostJWT ResponseMode = "form_post.jwt"
)

// IsJARM reports whether m is one of the JARM modes.
func IsJARM(m string) bool {
	switch ResponseMode(m) {
	case ModeJWT, ModeQueryJWT, ModeFragmentJWT, ModeFormPostJWT:
		return true
	}
	return false
}

// Errors surfaced by this package.
var (
	ErrUnsupportedMode = errors.New("jarm: unsupported response_mode")
)

// Payload is the set of claims a JARM response carries. Either Code or
// (Error, ErrorDescription) is populated for the success / failure cases.
type Payload struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

// Responder builds and sends JARM responses.
type Responder struct {
	signer   jwks.Signer
	issuer   string
	ttl      time.Duration
	formPost *template.Template
}

// Config configures a Responder.
type Config struct {
	Signer jwks.Signer
	// Issuer is the OP's issuer URL; embedded in `iss`.
	Issuer string
	// TTL is the response JWT lifetime; typically very short (default 120s).
	TTL time.Duration
}

// New constructs a Responder.
func New(cfg Config) (*Responder, error) {
	if cfg.Signer == nil || cfg.Issuer == "" {
		return nil, errors.New("jarm: signer and issuer required")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 120 * time.Second
	}
	tmpl, err := template.New("form_post").Parse(formPostHTML)
	if err != nil {
		return nil, fmt.Errorf("parse form_post template: %w", err)
	}
	return &Responder{
		signer:   cfg.Signer,
		issuer:   cfg.Issuer,
		ttl:      cfg.TTL,
		formPost: tmpl,
	}, nil
}

// Send signs the payload as a JWT and writes the response according to mode.
// audience is typically the client's client_id.
func (r *Responder) Send(
	ctx context.Context,
	w http.ResponseWriter,
	req *http.Request,
	mode ResponseMode,
	tenantID uuid.UUID,
	redirectURI, audience string,
	p Payload,
) error {
	signed, err := r.signResponse(ctx, tenantID, audience, p)
	if err != nil {
		return err
	}
	switch mode {
	case ModeJWT, ModeQueryJWT:
		return r.sendQuery(w, req, redirectURI, signed)
	case ModeFragmentJWT:
		return r.sendFragment(w, req, redirectURI, signed)
	case ModeFormPostJWT:
		return r.sendFormPost(w, redirectURI, signed)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedMode, mode)
	}
}

func (r *Responder) signResponse(ctx context.Context, tenantID uuid.UUID, audience string, p Payload) (string, error) {
	now := time.Now().UTC()
	builder := jwt.NewBuilder().
		Issuer(r.issuer).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(r.ttl))
	if p.Code != "" {
		_ = builder.Claim("code", p.Code)
	}
	if p.State != "" {
		_ = builder.Claim("state", p.State)
	}
	if p.Error != "" {
		_ = builder.Claim("error", p.Error)
	}
	if p.ErrorDescription != "" {
		_ = builder.Claim("error_description", p.ErrorDescription)
	}
	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("build JARM jwt: %w", err)
	}
	signed, err := r.signer.SignJWT(ctx, tenantID, tok)
	if err != nil {
		return "", fmt.Errorf("sign JARM jwt: %w", err)
	}
	return signed, nil
}

func (r *Responder) sendQuery(w http.ResponseWriter, req *http.Request, redirectURI, signed string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect_uri: %w", err)
	}
	q := u.Query()
	q.Set("response", signed)
	u.RawQuery = q.Encode()
	//nolint:gosec // redirect URI was validated against the client's registered allowlist
	http.Redirect(w, req, u.String(), http.StatusFound)
	return nil
}

func (r *Responder) sendFragment(w http.ResponseWriter, req *http.Request, redirectURI, signed string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect_uri: %w", err)
	}
	// fragment must not be URL-encoded as a whole; we splice the response
	// into the existing fragment (typically empty) using `&` if there's
	// already content.
	frag := u.Fragment
	if frag != "" {
		frag += "&"
	}
	frag += "response=" + url.QueryEscape(signed)
	u.Fragment = frag
	//nolint:gosec // redirect URI was validated against the client's registered allowlist
	http.Redirect(w, req, u.String(), http.StatusFound)
	return nil
}

func (r *Responder) sendFormPost(w http.ResponseWriter, redirectURI, signed string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	return r.formPost.Execute(w, map[string]string{
		"Action":   redirectURI,
		"Response": signed,
	})
}

// SplitResponse extracts (mode, baseMode) — useful when consumers want to
// match on the "real" response type (`code`, `none`, …) and the JARM
// transport separately. For "query.jwt" it returns ("query", "jwt"); for
// the bare "jwt" it returns ("query", "jwt") too.
func SplitResponse(mode string) (transport, base string) {
	m := strings.ToLower(mode)
	if m == "jwt" {
		return "query", "jwt"
	}
	if !strings.HasSuffix(m, ".jwt") {
		return m, ""
	}
	return strings.TrimSuffix(m, ".jwt"), "jwt"
}

const formPostHTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Redirecting…</title></head>
<body onload="document.forms[0].submit()">
<noscript><p>Click to continue:</p></noscript>
<form method="POST" action="{{.Action}}">
  <input type="hidden" name="response" value="{{.Response}}">
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>
`
