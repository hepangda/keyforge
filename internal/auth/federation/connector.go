// Package federation lets keyforge act as an OIDC RP against upstream
// identity providers (Google, Okta, another keyforge instance, etc.) and
// federate the resulting identity to a local user.
//
// One Connector instance covers one IdP. The connector lazily discovers
// the upstream's OIDC metadata on first use and caches it; PKCE and
// nonce are always used. The client secret (if any) is sealed via the
// same envelope helper that protects JWKS private keys.
package federation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by Connector.
var (
	ErrUnknownIdP       = errors.New("federation: unknown idp")
	ErrDiscoveryFailed  = errors.New("federation: discovery failed")
	ErrTokenExchange    = errors.New("federation: token exchange failed")
	ErrIDTokenInvalid   = errors.New("federation: id_token verification failed")
	ErrClaimMappingBad  = errors.New("federation: claim mapping invalid")
	ErrSubjectMissing   = errors.New("federation: upstream subject missing")
	ErrSecretDecryption = errors.New("federation: client secret decryption failed")
)

// ClaimMapping maps local field names to upstream claim names. Empty
// values fall back to the same name on both sides.
type ClaimMapping struct {
	Subject     string `json:"subject"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Mapped is the identity surfaced after a successful federation roundtrip.
type Mapped struct {
	Subject     string
	Email       string
	DisplayName string
	IDToken     string
	Raw         map[string]any
}

// Connector wraps the OIDC RP machinery for one upstream IdP.
type Connector struct {
	row          *db.IdpConnector
	mapping      ClaimMapping
	clientSecret string

	mu           sync.Mutex
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewConnector constructs a Connector from a stored row. The envelope is
// used to decrypt the client secret on demand; callers should reuse a
// single Connector for a given (idp_id) for the cache to be effective.
func NewConnector(row *db.IdpConnector, env *kcrypto.Envelope) (*Connector, error) {
	if row == nil {
		return nil, fmt.Errorf("federation: nil connector row")
	}
	mapping, err := decodeMapping(row.ClaimMapping)
	if err != nil {
		return nil, err
	}
	c := &Connector{row: row, mapping: mapping}
	if len(row.SecretCiphertext) > 0 && len(row.DEKCiphertext) > 0 {
		plain, decErr := env.OpenWithDEK(row.DEKCiphertext, row.SecretCiphertext)
		if decErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrSecretDecryption, decErr)
		}
		c.clientSecret = string(plain)
	}
	return c, nil
}

// Slug returns the per-tenant URL slug for this IdP.
func (c *Connector) Slug() string { return c.row.Slug }

// DisplayName returns the human-readable label for buttons.
func (c *Connector) DisplayName() string { return c.row.DisplayName }

// ID returns the connector's DB id.
func (c *Connector) ID() uuid.UUID { return c.row.ID }

// ensure lazily discovers the upstream OIDC metadata and builds the
// oauth2.Config + verifier. Discovery is cached for the lifetime of the
// Connector; restart picks up rotated keys via the upstream JWKS fetch.
func (c *Connector) ensure(ctx context.Context, redirectURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && c.oauth2Config != nil && c.oauth2Config.RedirectURL == redirectURL {
		return nil
	}
	p, err := oidc.NewProvider(ctx, c.row.Issuer)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}
	c.provider = p
	c.oauth2Config = &oauth2.Config{
		ClientID:     c.row.ClientID,
		ClientSecret: c.clientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       c.row.Scopes,
	}
	c.verifier = p.Verifier(&oidc.Config{ClientID: c.row.ClientID})
	return nil
}

// AuthCodeRequest captures everything needed to redirect the browser to
// the upstream IdP's /authorize endpoint.
type AuthCodeRequest struct {
	URL          string
	State        string
	Nonce        string
	PKCEVerifier string
}

// BuildAuthCodeRequest returns the URL the browser must hit at the
// upstream. The state/nonce/PKCE-verifier strings must be persisted on
// the auth_request row so the callback handler can match them.
func (c *Connector) BuildAuthCodeRequest(ctx context.Context, redirectURL string) (*AuthCodeRequest, error) {
	if err := c.ensure(ctx, redirectURL); err != nil {
		return nil, err
	}
	state, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()
	url := c.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.AccessTypeOnline,
	)
	return &AuthCodeRequest{
		URL:          url,
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
	}, nil
}

// Exchange completes the token exchange and validates the returned
// id_token (signature, issuer, audience, nonce).
func (c *Connector) Exchange(ctx context.Context, redirectURL, code, pkceVerifier, expectedNonce string) (*Mapped, error) {
	if err := c.ensure(ctx, redirectURL); err != nil {
		return nil, err
	}
	tok, err := c.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenExchange, err)
	}
	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, fmt.Errorf("%w: missing id_token", ErrIDTokenInvalid)
	}
	idt, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDTokenInvalid, err)
	}
	if idt.Nonce != expectedNonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrIDTokenInvalid)
	}
	raw := map[string]any{}
	if err := idt.Claims(&raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDTokenInvalid, err)
	}
	m := c.applyMapping(raw, idt.Subject)
	if m.Subject == "" {
		return nil, ErrSubjectMissing
	}
	m.IDToken = rawIDToken
	return m, nil
}

func (c *Connector) applyMapping(claims map[string]any, fallbackSubject string) *Mapped {
	pick := func(key, def string) string {
		if v, ok := claims[key]; ok {
			if s, ok2 := v.(string); ok2 && s != "" {
				return s
			}
		}
		return def
	}
	sub := pick(orDefault(c.mapping.Subject, "sub"), fallbackSubject)
	email := pick(orDefault(c.mapping.Email, "email"), "")
	dn := pick(orDefault(c.mapping.DisplayName, "name"), "")
	return &Mapped{Subject: sub, Email: email, DisplayName: dn, Raw: claims}
}

// decodeMapping reads the JSONB column. Empty or null becomes a
// zero-value ClaimMapping (the connector then uses default upstream
// claim names).
func decodeMapping(raw []byte) (ClaimMapping, error) {
	cm := ClaimMapping{}
	if len(raw) == 0 || string(raw) == "null" {
		return cm, nil
	}
	if err := jsonUnmarshal(raw, &cm); err != nil {
		return cm, fmt.Errorf("%w: %w", ErrClaimMappingBad, err)
	}
	return cm, nil
}

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// randomToken returns a URL-safe random token of n raw bytes.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
