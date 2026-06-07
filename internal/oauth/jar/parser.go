// Package jar implements JWT-Secured Authorization Request parsing per
// RFC 9101. A client may carry the authorization parameters as a signed
// (and optionally encrypted) JWT in the `request` parameter, or POST it
// out-of-band and reference it via `request_uri`. keyforge's authorize
// endpoint delegates to jar.Parse for `request` and to par.Redeem for
// `request_uri`.
package jar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/storage/clients"
)

// Errors surfaced by the parser.
var (
	ErrNoClient    = errors.New("jar: no client_id in form or in request object")
	ErrIssMismatch = errors.New("jar: request object iss does not match client_id")
	ErrNoKeySet    = errors.New("jar: client has no jwks or jwks_uri configured")
	ErrInvalidJWT  = errors.New("jar: request object failed signature verification")
)

// Parser resolves a `request` JWT into its claims.
type Parser struct {
	// Audience is the issuer URL that the request object's `aud` claim
	// must include. Usually the OP's issuer.
	Audience string
	// HTTPClient fetches remote jwks_uri documents. Nil falls back to
	// http.DefaultClient with a short timeout.
	HTTPClient *http.Client
	// SkewTolerance is allowable iat/exp clock drift.
	SkewTolerance time.Duration
}

// New constructs a Parser.
func New(audience string) *Parser {
	return &Parser{
		Audience:      audience,
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		SkewTolerance: 60 * time.Second,
	}
}

// Parse verifies the request-object JWT against the client's registered
// key set and returns its claims as a flat map suitable for merging with
// query/form parameters. The client argument is the row already loaded by
// the authorize endpoint based on the outer client_id form value.
func (p *Parser) Parse(ctx context.Context, raw string, cli *clients.Client) (map[string]any, error) {
	if raw == "" {
		return nil, errors.New("jar: empty request object")
	}
	// First parse insecurely to discover the issuer; we'll re-verify with
	// the proper key set.
	insecure, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJWT, err)
	}
	if insecure.Issuer() != "" && insecure.Issuer() != cli.ClientID {
		return nil, ErrIssMismatch
	}

	set, err := p.resolveKeySet(ctx, cli)
	if err != nil {
		return nil, err
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(p.SkewTolerance),
		jwt.WithIssuer(cli.ClientID),
	}
	if p.Audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(p.Audience))
	}

	tok, err := jwt.Parse([]byte(raw), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJWT, err)
	}

	// Flatten all claims to map[string]any so the caller can merge.
	out, err := tok.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("flatten claims: %w", err)
	}
	return out, nil
}

func (p *Parser) resolveKeySet(ctx context.Context, cli *clients.Client) (jwk.Set, error) {
	if len(cli.JWKS) > 0 {
		set, err := jwk.Parse(cli.JWKS)
		if err != nil {
			return nil, fmt.Errorf("parse inline jwks: %w", err)
		}
		return set, nil
	}
	if cli.JWKSURI == "" {
		return nil, ErrNoKeySet
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.JWKSURI, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks_uri: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks_uri %s returned %d", cli.JWKSURI, resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode jwks body: %w", err)
	}
	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse remote jwks: %w", err)
	}
	return set, nil
}
