package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/storage/clients"
)

// JWTAssertionType is the OAuth 2.0 client_assertion_type value defined by
// RFC 7521 / RFC 7523 §2.2.
const JWTAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// PrivateKeyJWTMethod authenticates clients via a signed JWT assertion per
// RFC 7523 §2.2. The assertion is signed by a private key held by the
// client; keyforge resolves the matching public JWK either inline from the
// client's stored `jwks` JSONB column or remotely from its `jwks_uri`.
type PrivateKeyJWTMethod struct {
	// Audience is the token endpoint URL. The assertion's `aud` claim must
	// include this value.
	Audience string
	// JTIStore detects replay of the same jti within the assertion lifetime.
	// Pass nil to skip replay detection (single-instance dev only).
	JTIStore JTIStore
	// HTTPClient fetches remote jwks_uri documents. Nil falls back to
	// http.DefaultClient with a short timeout.
	HTTPClient *http.Client
	// SkewTolerance is the maximum +/- drift allowed between client and
	// server clocks when validating iat/exp.
	SkewTolerance time.Duration
}

// JTIStore records consumed JWT IDs to defeat replay.
type JTIStore interface {
	// SeenJTI records jti as consumed for at least ttl; returns true if
	// the jti has already been seen.
	SeenJTI(ctx context.Context, jti string, ttl time.Duration) (bool, error)
}

// NewPrivateKeyJWTMethod constructs the method.
func NewPrivateKeyJWTMethod(audience string, jtiStore JTIStore) *PrivateKeyJWTMethod {
	return &PrivateKeyJWTMethod{
		Audience:      audience,
		JTIStore:      jtiStore,
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		SkewTolerance: 60 * time.Second,
	}
}

// Name implements Method.
func (PrivateKeyJWTMethod) Name() MethodName { return MethodPrivateKeyJWT }

// Authenticate implements Method.
func (m *PrivateKeyJWTMethod) Authenticate(ctx context.Context, r *http.Request, lookup ClientLookup) (*Result, error) {
	if r.PostFormValue("client_assertion_type") != JWTAssertionType {
		return nil, ErrUnknownClient
	}
	assertion := r.PostFormValue("client_assertion")
	if assertion == "" {
		return nil, ErrInvalidClient
	}

	// Parse insecurely first to discover the issuer (= client_id), then
	// re-parse with the appropriate key set for verification.
	insecureTok, err := jwt.ParseInsecure([]byte(assertion))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed assertion: %w", ErrInvalidClient, err)
	}
	clientID := insecureTok.Issuer()
	if clientID == "" {
		return nil, fmt.Errorf("%w: assertion missing iss", ErrInvalidClient)
	}
	formClientID := FormClientID(r)
	if formClientID != "" && formClientID != clientID {
		return nil, fmt.Errorf("%w: assertion iss does not match form client_id", ErrInvalidClient)
	}

	cli, err := lookup.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	if cli.TokenEndpointAuthMethod != string(MethodPrivateKeyJWT) {
		return nil, ErrMethodMismatch
	}

	keySet, err := m.resolveKeySet(ctx, cli)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidClient, err)
	}

	tok, err := jwt.Parse(
		[]byte(assertion),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(m.SkewTolerance),
		jwt.WithIssuer(clientID),
		jwt.WithSubject(clientID),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: jwt verify: %w", ErrInvalidClient, err)
	}

	// Audience must contain the configured token-endpoint URL.
	if !audienceMatches(tok.Audience(), m.Audience) {
		return nil, fmt.Errorf("%w: aud mismatch", ErrInvalidClient)
	}

	// Replay detection.
	if m.JTIStore != nil {
		jti := tok.JwtID()
		if jti == "" {
			return nil, fmt.Errorf("%w: assertion missing jti", ErrInvalidClient)
		}
		ttl := time.Until(tok.Expiration()) + m.SkewTolerance
		seen, serr := m.JTIStore.SeenJTI(ctx, jti, ttl)
		if serr != nil {
			return nil, fmt.Errorf("jti store: %w", serr)
		}
		if seen {
			return nil, fmt.Errorf("%w: jti replay", ErrInvalidClient)
		}
	}

	return &Result{Client: cli, Method: MethodPrivateKeyJWT}, nil
}

func (m *PrivateKeyJWTMethod) resolveKeySet(ctx context.Context, cli *clients.Client) (jwk.Set, error) {
	if len(cli.JWKS) > 0 {
		set, err := jwk.Parse(cli.JWKS)
		if err != nil {
			return nil, fmt.Errorf("parse inline jwks: %w", err)
		}
		return set, nil
	}
	if cli.JWKSURI == "" {
		return nil, errors.New("client has neither inline jwks nor jwks_uri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.JWKSURI, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	client := m.HTTPClient
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
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode jwks_uri body: %w", err)
	}
	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse jwks_uri body: %w", err)
	}
	return set, nil
}

func audienceMatches(audList []string, want string) bool {
	for _, a := range audList {
		if a == want {
			return true
		}
		// some clients include just the host; we accept exact only.
		if strings.EqualFold(a, want) {
			return true
		}
	}
	return false
}

// jws is used implicitly by jwt parsing; keep the import live for future
// helpers (e.g. inspecting the header alg).
var _ = jws.KeyIDKey
