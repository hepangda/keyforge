// Package dpop implements RFC 9449: Demonstrating Proof of Possession at
// the application layer.
//
// A DPoP proof is a short-lived JWT signed by the client's own key and
// presented in the `DPoP` HTTP header. When a client mints a token at
// /oauth/token with a DPoP proof attached, keyforge stores the public-key
// thumbprint (`jkt`) on the access-token row. Subsequent uses at
// /userinfo, /introspect, or any DPoP-aware resource server MUST present
// a fresh DPoP proof whose key thumbprint matches.
package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// HeaderName is the request header carrying the DPoP proof.
const HeaderName = "DPoP"

// TokenType is the value the token endpoint uses in the token_type field
// (and the resource server expects in the Authorization scheme) when the
// access token is DPoP-bound.
const TokenType = "DPoP"

// Errors surfaced by the package.
var (
	ErrMissingProof       = errors.New("dpop: missing proof header")
	ErrMalformedProof     = errors.New("dpop: proof JWT is malformed")
	ErrBadType            = errors.New("dpop: proof typ header is not dpop+jwt")
	ErrSymmetricAlg       = errors.New("dpop: symmetric algorithms are forbidden")
	ErrMissingJWK         = errors.New("dpop: proof header missing jwk")
	ErrPrivateKey         = errors.New("dpop: proof jwk must be public-only")
	ErrHTUMismatch        = errors.New("dpop: htu does not match request URL")
	ErrHTMMismatch        = errors.New("dpop: htm does not match request method")
	ErrSkew               = errors.New("dpop: proof iat outside allowed skew")
	ErrReplay             = errors.New("dpop: proof jti already seen")
	ErrATHMismatch        = errors.New("dpop: ath does not match access token hash")
	ErrThumbprintMismatch = errors.New("dpop: jkt does not match bound access token")
	ErrInvalidSignature   = errors.New("dpop: invalid signature")
)

// Validator validates DPoP proofs.
type Validator struct {
	SkewTolerance time.Duration
	Replay        ReplayCache
}

// New constructs a Validator with sane defaults.
func New(skew time.Duration, replay ReplayCache) *Validator {
	if skew == 0 {
		skew = 60 * time.Second
	}
	return &Validator{SkewTolerance: skew, Replay: replay}
}

// Proof is a successfully-validated DPoP proof.
type Proof struct {
	JKT      string // base64url-encoded SHA-256 JWK thumbprint
	JTI      string
	HTM      string
	HTU      string
	IssuedAt time.Time
	// ATH, when non-empty, is the base64url(SHA-256(access_token)) claim
	// the spec requires at the resource server.
	ATH string
}

// Validate parses + verifies the proof attached to r and returns its key
// thumbprint and claims. When boundAccessToken is non-empty, the proof
// MUST carry an `ath` claim equal to base64url(SHA-256(boundAccessToken)).
//
// htuOverride lets callers force the htu comparison to a canonical URL
// (e.g. when the OP sits behind a reverse proxy and r.Host doesn't reflect
// the public hostname). Pass "" to derive it from the request directly.
func (v *Validator) Validate(r *http.Request, htuOverride, boundAccessToken string) (*Proof, error) {
	raw := r.Header.Get(HeaderName)
	if raw == "" {
		return nil, ErrMissingProof
	}

	// Inspect the protected header without verifying first, to extract the
	// embedded JWK and validate alg/typ.
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedProof, err)
	}
	if len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("%w: expected single signature", ErrMalformedProof)
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if hdr == nil {
		return nil, fmt.Errorf("%w: missing protected headers", ErrMalformedProof)
	}
	if t := hdr.Type(); t != "dpop+jwt" {
		return nil, fmt.Errorf("%w (got %q)", ErrBadType, t)
	}
	alg := hdr.Algorithm()
	if !isAsymmetric(alg) {
		return nil, ErrSymmetricAlg
	}
	jwkKey := hdr.JWK()
	if jwkKey == nil {
		return nil, ErrMissingJWK
	}
	// Reject private parameters by checking the type — jwx exposes a
	// `Materialize` you can compare, but a simpler rule is: the public form
	// of jwkKey must equal jwkKey itself.
	pub, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMissingJWK, err)
	}
	if !sameJWK(jwkKey, pub) {
		return nil, ErrPrivateKey
	}

	// Verify the JWT signature against the embedded jwk.
	tok, err := jwt.Parse(
		[]byte(raw),
		jwt.WithKey(alg, jwkKey),
		jwt.WithValidate(false), // we'll do iat/exp manually
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	// htm / htu
	htmClaim, _ := tok.Get("htm")
	htuClaim, _ := tok.Get("htu")
	jtiClaim, _ := tok.Get("jti")
	htm, _ := htmClaim.(string)
	htu, _ := htuClaim.(string)
	jti, _ := jtiClaim.(string)
	if !strings.EqualFold(htm, r.Method) {
		return nil, fmt.Errorf("%w (got %q want %q)", ErrHTMMismatch, htm, r.Method)
	}
	wantHTU := htuOverride
	if wantHTU == "" {
		wantHTU = requestURL(r)
	}
	if !equalURL(htu, wantHTU) {
		return nil, fmt.Errorf("%w (got %q want %q)", ErrHTUMismatch, htu, wantHTU)
	}

	// iat skew
	iat := tok.IssuedAt()
	if iat.IsZero() {
		return nil, fmt.Errorf("%w: missing iat", ErrSkew)
	}
	delta := time.Since(iat)
	if delta < -v.SkewTolerance || delta > v.SkewTolerance {
		return nil, fmt.Errorf("%w: delta=%s", ErrSkew, delta)
	}

	// jti replay
	if v.Replay != nil {
		if jti == "" {
			return nil, fmt.Errorf("%w: missing jti", ErrReplay)
		}
		seen, rerr := v.Replay.Seen(jti, v.SkewTolerance*2)
		if rerr != nil {
			return nil, fmt.Errorf("dpop replay store: %w", rerr)
		}
		if seen {
			return nil, ErrReplay
		}
	}

	// ath
	if boundAccessToken != "" {
		athClaim, _ := tok.Get("ath")
		ath, _ := athClaim.(string)
		want := ath256(boundAccessToken)
		if ath != want {
			return nil, ErrATHMismatch
		}
	}

	// Thumbprint
	tp, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)

	return &Proof{
		JKT:      jkt,
		JTI:      jti,
		HTM:      htm,
		HTU:      htu,
		IssuedAt: iat,
		ATH:      ath256(boundAccessToken),
	}, nil
}

// ATHFor returns the canonical base64url(SHA-256(token)) used as the `ath`
// claim in DPoP proofs presented to resource servers.
func ATHFor(accessToken string) string {
	return ath256(accessToken)
}

func ath256(at string) string {
	if at == "" {
		return ""
	}
	h := sha256.Sum256([]byte(at))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	} else if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

func equalURL(a, b string) bool {
	// Allow trailing-slash and case differences in scheme/host only;
	// path/query must match exactly.
	if a == b {
		return true
	}
	return strings.EqualFold(strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/"))
}

func isAsymmetric(a jwa.SignatureAlgorithm) bool {
	switch a {
	case jwa.RS256, jwa.RS384, jwa.RS512,
		jwa.PS256, jwa.PS384, jwa.PS512,
		jwa.ES256, jwa.ES384, jwa.ES512,
		jwa.EdDSA:
		return true
	}
	return false
}

func sameJWK(a, b jwk.Key) bool {
	ta, errA := a.Thumbprint(crypto.SHA256)
	tb, errB := b.Thumbprint(crypto.SHA256)
	if errA != nil || errB != nil {
		return false
	}
	return string(ta) == string(tb)
}
