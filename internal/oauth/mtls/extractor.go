// Package mtls extracts and binds TLS client certificates for OAuth 2.0
// mutual-TLS client authentication (RFC 8705) and certificate-bound access
// tokens. In production, keyforge can run with a direct TLS-terminating
// listener (with ClientAuth: RequestClientCert) or behind an ingress that
// presents the client cert in a forwarded header.
package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// HeaderFormat enumerates the wire encodings that proxies use to forward
// the client cert. Pick the one your ingress is configured to emit.
type HeaderFormat string

// Supported forwarded-cert header encodings.
const (
	// FormatRFC9440 follows draft-ietf-httpbis-client-cert-field (now RFC
	// 9440) — the cert is base64-encoded DER inside a Structured Field.
	FormatRFC9440 HeaderFormat = "rfc9440"
	// FormatXFCC follows nginx-ingress' x-forwarded-client-cert: a
	// URL-encoded PEM-style block (with %0A line breaks) optionally
	// alongside DN= and Hash= subfields.
	FormatXFCC HeaderFormat = "xfcc"
	// FormatPEM is the literal multi-line PEM block — used by some legacy
	// gateways that don't bother URL-encoding it.
	FormatPEM HeaderFormat = "pem"
)

// Errors surfaced by extractors.
var (
	ErrNoClientCert = errors.New("mtls: no client certificate on request")
	ErrBadHeader    = errors.New("mtls: client certificate header is malformed")
)

// CertExtractor returns the leaf client certificate associated with a
// request, or ErrNoClientCert if none is present. Implementations differ in
// whether they read the live TLS connection or trust a proxy-supplied
// header.
type CertExtractor interface {
	Extract(r *http.Request) (*x509.Certificate, error)
}

// DirectExtractor reads the certificate from r.TLS.PeerCertificates.
// Use this when keyforge terminates TLS itself.
type DirectExtractor struct{}

// Extract implements CertExtractor.
func (DirectExtractor) Extract(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrNoClientCert
	}
	return r.TLS.PeerCertificates[0], nil
}

// HeaderExtractor reads the certificate from a request header forwarded by
// a trusted reverse proxy. The header name and encoding format must match
// what the ingress is configured to send.
type HeaderExtractor struct {
	HeaderName   string
	Format       HeaderFormat
	TrustedCIDRs []*net.IPNet
}

// NewHeaderExtractor configures a HeaderExtractor. If trustedCIDRs is
// non-empty, Extract rejects requests whose direct peer is not in the
// trusted set — defending against clients that smuggle their own
// X-Forwarded-Client-Cert header.
func NewHeaderExtractor(name string, format HeaderFormat, trustedCIDRs []*net.IPNet) *HeaderExtractor {
	return &HeaderExtractor{
		HeaderName:   name,
		Format:       format,
		TrustedCIDRs: trustedCIDRs,
	}
}

// Extract implements CertExtractor.
func (h *HeaderExtractor) Extract(r *http.Request) (*x509.Certificate, error) {
	if len(h.TrustedCIDRs) > 0 {
		peer := remoteIP(r)
		ip := net.ParseIP(peer)
		if ip == nil || !anyContains(h.TrustedCIDRs, ip) {
			return nil, ErrNoClientCert
		}
	}
	raw := r.Header.Get(h.HeaderName)
	if raw == "" {
		return nil, ErrNoClientCert
	}
	der, err := decodeHeader(raw, h.Format)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadHeader, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadHeader, err)
	}
	return cert, nil
}

func decodeHeader(raw string, format HeaderFormat) ([]byte, error) {
	switch format {
	case FormatRFC9440:
		// Structured-field byte sequence: a colon-delimited base64 token
		// optionally preceded by parameters. We accept either ":<b64>:" or
		// the bare base64.
		s := strings.TrimSpace(raw)
		s = strings.Trim(s, ":")
		return base64.StdEncoding.DecodeString(s)
	case FormatXFCC:
		// nginx-ingress wraps the cert in a URL-encoded "Cert=" subfield:
		//   "By=...;Hash=...;Cert=\"-----BEGIN CERT-----\\nMIIB...\\n-----END\""
		// Extract the Cert subfield, URL-decode, parse PEM.
		certPart := raw
		if idx := strings.Index(strings.ToLower(raw), "cert="); idx >= 0 {
			certPart = raw[idx+len("cert="):]
		}
		certPart = strings.Trim(certPart, " \"")
		dec, err := url.QueryUnescape(certPart)
		if err != nil {
			dec = certPart
		}
		dec = strings.ReplaceAll(dec, "\\n", "\n")
		return pemDecode(dec)
	case FormatPEM:
		return pemDecode(raw)
	default:
		return nil, fmt.Errorf("unknown header format %q", format)
	}
}

func pemDecode(s string) ([]byte, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return block.Bytes, nil
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func anyContains(cidrs []*net.IPNet, ip net.IP) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// Thumbprint returns the base64url-encoded SHA-256 of the certificate's DER
// encoding, per RFC 8705 §3. This is the value stored as `cnf.x5t#S256`
// on certificate-bound access tokens.
func Thumbprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
