// Package crypto implements keyforge's envelope encryption and key
// generation primitives. JWKS signing keys are stored in Postgres with
// their private material encrypted under a per-row data encryption key (DEK);
// the DEK itself is wrapped by a master key (KEK) sourced from
// KEYFORGE_JWKS__MASTER_KEY.
//
// All AEAD operations use AES-256-GCM. The wire format embeds a single-byte
// version tag so we can rotate cipher constructions in the future without
// breaking existing ciphertexts.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	envelopeVersion byte = 0x01
	nonceLen        int  = 12
	kekLen          int  = 32 // AES-256
	dekLen          int  = 32 // AES-256
)

// Errors surfaced by this package.
var (
	ErrShortCiphertext = errors.New("envelope: ciphertext too short")
	ErrBadVersion      = errors.New("envelope: unknown version byte")
	ErrKEKLength       = errors.New("envelope: master key must be 32 bytes after decoding")
)

// Envelope wraps and unwraps secrets using a key encryption key (KEK).
//
// Wrap returns ciphertext laid out as: version || nonce || gcm-output.
// Unwrap reverses the same layout. Both operations are constant-time
// against malformed inputs (GCM authentication failure is non-malleable).
type Envelope struct {
	kek []byte
}

// NewEnvelope constructs an Envelope from a 32-byte KEK. Use ParseMasterKey
// when the key arrives as a base64- or hex-encoded string from configuration.
func NewEnvelope(kek []byte) (*Envelope, error) {
	if len(kek) != kekLen {
		return nil, ErrKEKLength
	}
	cp := make([]byte, kekLen)
	copy(cp, kek)
	return &Envelope{kek: cp}, nil
}

// ParseMasterKey interprets s as either base64 (standard or URL), hex, or as
// raw 32 ASCII bytes. The configured KEYFORGE_JWKS__MASTER_KEY may be
// encoded in any of these forms; the function picks whichever yields a
// 32-byte secret.
func ParseMasterKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hexDecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == kekLen {
			return b, nil
		}
	}
	// Last resort: raw ASCII bytes if exactly 32.
	if len(s) == kekLen {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("%w (provided length %d)", ErrKEKLength, len(s))
}

// Wrap encrypts a plaintext DEK under the KEK and returns the wire-format
// ciphertext.
func (e *Envelope) Wrap(plaintext []byte) ([]byte, error) {
	return seal(e.kek, plaintext)
}

// Unwrap reverses Wrap.
func (e *Envelope) Unwrap(ciphertext []byte) ([]byte, error) {
	return open(e.kek, ciphertext)
}

// SealWithDEK generates a fresh 32-byte DEK, encrypts plaintext under it,
// wraps the DEK under the KEK, and returns (wrappedDEK, ciphertext).
// This is the operation keyforge uses to store JWKS private keys: the row
// holds the DEK ciphertext and the message ciphertext separately so the DEK
// can be cached or rotated independently.
func (e *Envelope) SealWithDEK(plaintext []byte) (wrappedDEK, ciphertext []byte, err error) {
	dek := make([]byte, dekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("generate dek: %w", err)
	}
	ct, err := seal(dek, plaintext)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := e.Wrap(dek)
	if err != nil {
		return nil, nil, err
	}
	return wrapped, ct, nil
}

// OpenWithDEK reverses SealWithDEK.
func (e *Envelope) OpenWithDEK(wrappedDEK, ciphertext []byte) ([]byte, error) {
	dek, err := e.Unwrap(wrappedDEK)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	return open(dek, ciphertext)
}

func seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := make([]byte, 0, 1+nonceLen+len(plaintext)+aead.Overhead())
	out = append(out, envelopeVersion)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, []byte{envelopeVersion})
	return out, nil
}

func open(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 1+nonceLen {
		return nil, ErrShortCiphertext
	}
	if ciphertext[0] != envelopeVersion {
		return nil, ErrBadVersion
	}
	nonce := ciphertext[1 : 1+nonceLen]
	body := ciphertext[1+nonceLen:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, body, []byte{envelopeVersion})
	if err != nil {
		return nil, fmt.Errorf("aead open: %w", err)
	}
	return plaintext, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func hexDecodeString(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexNibble(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	}
	return 0, fmt.Errorf("non-hex byte %q", b)
}
