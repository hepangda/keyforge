// Package password provides argon2id password hashing and verification.
//
// The encoded form is the standard PHC string:
//
//	$argon2id$v=19$m=65536,t=2,p=4$<base64-salt>$<base64-hash>
//
// New hashes are minted at the parameters in DefaultParams; verification
// accepts hashes with any parameters (so old hashes survive a tuning bump
// without forcing a rehash).
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Errors surfaced by this package.
var (
	ErrInvalidHash         = errors.New("password: hash is malformed")
	ErrIncompatibleVersion = errors.New("password: argon2 version mismatch")
	ErrMismatched          = errors.New("password: hash and plaintext do not match")
)

// Params are the argon2id cost knobs. Defaults follow the 2026 baseline:
// time=2, memory=64 MiB, parallelism=4, 32-byte tag.
type Params struct {
	TimeCost    uint32
	MemoryKiB   uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultParams returns the keyforge-blessed argon2id parameters.
func DefaultParams() Params {
	return Params{
		TimeCost:    2,
		MemoryKiB:   64 * 1024,
		Parallelism: 4,
		SaltLen:     16,
		KeyLen:      32,
	}
}

// Hash hashes plaintext with the given parameters and returns the PHC string.
func Hash(plaintext string, p Params) (string, error) {
	if p.SaltLen == 0 {
		p = DefaultParams()
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	tag := argon2.IDKey([]byte(plaintext), salt, p.TimeCost, p.MemoryKiB, p.Parallelism, p.KeyLen)
	return encode(p, salt, tag), nil
}

// Verify returns nil iff plaintext re-derives the stored tag under the
// same parameters. The comparison is constant-time.
func Verify(stored, plaintext string) error {
	p, salt, tag, err := decode(stored)
	if err != nil {
		return err
	}
	candidate := argon2.IDKey([]byte(plaintext), salt, p.TimeCost, p.MemoryKiB, p.Parallelism, p.KeyLen)
	if subtle.ConstantTimeCompare(candidate, tag) != 1 {
		return ErrMismatched
	}
	return nil
}

// NeedsRehash returns true iff the stored hash was produced at parameters
// weaker than `want`. Callers should rehash on next successful login.
func NeedsRehash(stored string, want Params) bool {
	p, _, _, err := decode(stored)
	if err != nil {
		return true
	}
	return p.TimeCost < want.TimeCost ||
		p.MemoryKiB < want.MemoryKiB ||
		p.Parallelism < want.Parallelism ||
		p.KeyLen < want.KeyLen
}

func encode(p Params, salt, tag []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.MemoryKiB, p.TimeCost, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(tag),
	)
}

func decode(s string) (Params, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return Params{}, nil, nil, ErrIncompatibleVersion
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.TimeCost, &p.Parallelism); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	tag, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLen = uint32(len(salt)) //nolint:gosec // PHC-decoded salt is bounded by base64 length
	p.KeyLen = uint32(len(tag))   //nolint:gosec // PHC-decoded tag is bounded by base64 length
	return p, salt, tag, nil
}
