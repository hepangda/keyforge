// Package jwks owns the lifecycle of keyforge's JSON Web Key Sets: generating
// signing keypairs, storing private material encrypted at rest, publishing
// the corresponding public keys at /.well-known/jwks.json, rotating keys on
// a schedule, and signing arbitrary JWS payloads on behalf of OIDC ID tokens,
// JAR, JARM, and DPoP server proofs.
//
// The Postgres-backed implementation lives in this file; an in-memory fake
// for tests lives in internal/testsupport.
package jwks

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by Store implementations.
var (
	ErrNoActiveKey = errors.New("jwks: no active signing key")
	ErrKeyNotFound = errors.New("jwks: key not found")
)

// Use values follow RFC 7517 §4.2.
const (
	UseSig = "sig"
	UseEnc = "enc"
)

// Status values match the jwks_keys.status CHECK constraint.
const (
	StatusActive  = "active"
	StatusRotated = "rotated"
	StatusRetired = "retired"
)

// Key is a fully hydrated signing key including its decrypted private
// material. Production callers should treat the PrivateKey field as sensitive
// and avoid passing it to functions that might log it.
type Key struct {
	ID         uuid.UUID
	TenantID   *uuid.UUID // nil for the global keyset
	KID        string
	Alg        kcrypto.Algorithm
	Use        string
	Status     string
	PrivateKey any
	PublicKey  any
	PublicPEM  []byte
	CreatedAt  time.Time
	RotatedAt  *time.Time
	RetiredAt  *time.Time
}

// JWK returns the lestrrat-go/jwx representation of the key's PUBLIC half,
// pre-populated with kid/alg/use. The private half is never embedded; this
// is what /.well-known/jwks.json publishes.
func (k *Key) JWK() (jwk.Key, error) {
	pub, err := jwk.FromRaw(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwk from raw public: %w", err)
	}
	if err := pub.Set(jwk.KeyIDKey, k.KID); err != nil {
		return nil, err
	}
	if err := pub.Set(jwk.AlgorithmKey, string(k.Alg)); err != nil {
		return nil, err
	}
	if err := pub.Set(jwk.KeyUsageKey, k.Use); err != nil {
		return nil, err
	}
	return pub, nil
}

// Store is the persistence contract for signing keys.
type Store interface {
	// Active returns the current active signing key for the tenant scope.
	// Pass uuid.Nil to read the global keyset.
	Active(ctx context.Context, tenantID uuid.UUID, use string) (*Key, error)

	// PublicSet returns every active+rotated key visible to the tenant
	// (including the global keys), as a JWK Set. It is what the JWKS
	// endpoint should serve.
	PublicSet(ctx context.Context, tenantID uuid.UUID) (jwk.Set, error)

	// Rotate generates a new active key, marks the previous active key as
	// rotated, and returns the new one.
	Rotate(ctx context.Context, tenantID uuid.UUID, alg kcrypto.Algorithm, use string) (*Key, error)

	// EnsureActive returns the active key, creating one if none exists.
	EnsureActive(ctx context.Context, tenantID uuid.UUID, alg kcrypto.Algorithm, use string) (*Key, error)

	// Sweep moves rotated keys past the retention window into 'retired'
	// status and deletes any retired keys older than gracePeriod.
	Sweep(ctx context.Context, retainAfterRotate, gracePeriod time.Duration) error
}

// Clock is injected so tests can advance time deterministically.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// SystemClock returns the production wall clock.
func SystemClock() Clock { return realClock{} }

// PostgresStore is the Postgres-backed Store. A public-set cache shaves the
// per-request cost off the JWKS HTTP handler.
type PostgresStore struct {
	pool *pgxpool.Pool
	q    *db.Queries
	env  *kcrypto.Envelope
	clk  Clock

	cacheMu  sync.RWMutex
	cache    map[uuid.UUID]cacheEntry
	cacheTTL time.Duration
}

type cacheEntry struct {
	set     jwk.Set
	written time.Time
}

// NewPostgresStore wires a Postgres-backed Store.
func NewPostgresStore(pool *pgxpool.Pool, env *kcrypto.Envelope, clk Clock) *PostgresStore {
	if clk == nil {
		clk = SystemClock()
	}
	return &PostgresStore{
		pool:     pool,
		q:        db.New(pool),
		env:      env,
		clk:      clk,
		cache:    make(map[uuid.UUID]cacheEntry),
		cacheTTL: 60 * time.Second,
	}
}

// Active implements Store.
func (s *PostgresStore) Active(ctx context.Context, tenantID uuid.UUID, use string) (*Key, error) {
	row, err := s.q.GetActiveJWKSKey(ctx, db.GetActiveJWKSKeyParams{
		TenantID: nullableUUID(tenantID),
		Use:      use,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoActiveKey
		}
		return nil, fmt.Errorf("active key: %w", err)
	}
	return s.hydrate(row)
}

// PublicSet implements Store.
func (s *PostgresStore) PublicSet(ctx context.Context, tenantID uuid.UUID) (jwk.Set, error) {
	now := s.clk.Now()
	s.cacheMu.RLock()
	if e, ok := s.cache[tenantID]; ok && now.Sub(e.written) < s.cacheTTL {
		set := e.set
		s.cacheMu.RUnlock()
		return set, nil
	}
	s.cacheMu.RUnlock()

	rows, err := s.q.ListPublicJWKSKeys(ctx, nullableUUID(tenantID))
	if err != nil {
		return nil, fmt.Errorf("list public keys: %w", err)
	}

	set := jwk.NewSet()
	for _, row := range rows {
		k, herr := s.hydratePublic(row)
		if herr != nil {
			return nil, herr
		}
		jk, jerr := k.JWK()
		if jerr != nil {
			return nil, jerr
		}
		if err := set.AddKey(jk); err != nil {
			return nil, fmt.Errorf("add jwk: %w", err)
		}
	}

	s.cacheMu.Lock()
	s.cache[tenantID] = cacheEntry{set: set, written: now}
	s.cacheMu.Unlock()
	return set, nil
}

// Rotate implements Store.
func (s *PostgresStore) Rotate(ctx context.Context, tenantID uuid.UUID, alg kcrypto.Algorithm, use string) (*Key, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)

	current, err := q.GetActiveJWKSKey(ctx, db.GetActiveJWKSKeyParams{
		TenantID: nullableUUID(tenantID),
		Use:      use,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("read current active: %w", err)
	}
	now := s.clk.Now().UTC()
	if current != nil {
		if err := q.MarkJWKSKeyRotated(ctx, db.MarkJWKSKeyRotatedParams{
			ID:        current.ID,
			RotatedAt: pgtype.Timestamptz{Time: now, Valid: true},
		}); err != nil {
			return nil, fmt.Errorf("mark rotated: %w", err)
		}
	}

	kp, err := kcrypto.Generate(alg)
	if err != nil {
		return nil, err
	}
	wrappedDEK, ct, err := s.env.SealWithDEK(kp.PrivatePEM)
	if err != nil {
		return nil, fmt.Errorf("seal private: %w", err)
	}
	kid := computeKID(kp.PublicPEM)
	row, err := q.InsertJWKSKey(ctx, db.InsertJWKSKeyParams{
		TenantID:          nullableUUID(tenantID),
		KID:               kid,
		Alg:               string(alg),
		Use:               use,
		PublicPem:         string(kp.PublicPEM),
		PrivateCiphertext: ct,
		DEKCiphertext:     wrappedDEK,
		Status:            StatusActive,
		CreatedAt:         now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	s.invalidate(tenantID)
	return s.hydrate(row)
}

// EnsureActive implements Store.
func (s *PostgresStore) EnsureActive(ctx context.Context, tenantID uuid.UUID, alg kcrypto.Algorithm, use string) (*Key, error) {
	k, err := s.Active(ctx, tenantID, use)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, ErrNoActiveKey) {
		return nil, err
	}
	return s.Rotate(ctx, tenantID, alg, use)
}

// Sweep implements Store.
func (s *PostgresStore) Sweep(ctx context.Context, retainAfterRotate, gracePeriod time.Duration) error {
	now := s.clk.Now().UTC()
	if err := s.q.RetireJWKSKeysOlderThan(ctx, db.RetireJWKSKeysOlderThanParams{
		RotatedAt: pgtype.Timestamptz{Time: now.Add(-retainAfterRotate), Valid: true},
		RetiredAt: pgtype.Timestamptz{Time: now, Valid: true},
	}); err != nil {
		return fmt.Errorf("retire old: %w", err)
	}
	if err := s.q.DeleteRetiredJWKSKeys(ctx, pgtype.Timestamptz{
		Time:  now.Add(-gracePeriod),
		Valid: true,
	}); err != nil {
		return fmt.Errorf("delete retired: %w", err)
	}
	s.invalidateAll()
	return nil
}

func (s *PostgresStore) invalidate(tenantID uuid.UUID) {
	s.cacheMu.Lock()
	delete(s.cache, tenantID)
	delete(s.cache, uuid.Nil)
	s.cacheMu.Unlock()
}

func (s *PostgresStore) invalidateAll() {
	s.cacheMu.Lock()
	s.cache = make(map[uuid.UUID]cacheEntry)
	s.cacheMu.Unlock()
}

func (s *PostgresStore) hydrate(row *db.JwksKey) (*Key, error) {
	k, err := s.hydratePublic(row)
	if err != nil {
		return nil, err
	}
	privPEM, err := s.env.OpenWithDEK(row.DEKCiphertext, row.PrivateCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt private: %w", err)
	}
	priv, err := kcrypto.ParsePrivatePEM(privPEM)
	if err != nil {
		return nil, err
	}
	k.PrivateKey = priv
	return k, nil
}

func (s *PostgresStore) hydratePublic(row *db.JwksKey) (*Key, error) {
	pub, err := kcrypto.ParsePublicPEM([]byte(row.PublicPem))
	if err != nil {
		return nil, err
	}
	var tid *uuid.UUID
	if row.TenantID.Valid {
		v, ierr := pgUUIDToGoogle(row.TenantID)
		if ierr != nil {
			return nil, ierr
		}
		tid = &v
	}
	var rotated *time.Time
	if row.RotatedAt.Valid {
		t := row.RotatedAt.Time
		rotated = &t
	}
	var retired *time.Time
	if row.RetiredAt.Valid {
		t := row.RetiredAt.Time
		retired = &t
	}
	return &Key{
		ID:        row.ID,
		TenantID:  tid,
		KID:       row.KID,
		Alg:       kcrypto.Algorithm(row.Alg),
		Use:       row.Use,
		Status:    row.Status,
		PublicKey: pub,
		PublicPEM: []byte(row.PublicPem),
		CreatedAt: row.CreatedAt,
		RotatedAt: rotated,
		RetiredAt: retired,
	}, nil
}

func nullableUUID(u uuid.UUID) pgtype.UUID {
	if u == uuid.Nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: u, Valid: true}
}

func pgUUIDToGoogle(p pgtype.UUID) (uuid.UUID, error) {
	if !p.Valid {
		return uuid.Nil, nil
	}
	return uuid.FromBytes(p.Bytes[:])
}

// computeKID returns the base64url-encoded SHA-256 hash of the public key
// PEM, truncated to 32 chars. This gives stable, content-derived kids that
// never collide across keys.
func computeKID(publicPEM []byte) string {
	h := sha256.Sum256(publicPEM)
	enc := base64.RawURLEncoding.EncodeToString(h[:])
	if len(enc) > 32 {
		enc = enc[:32]
	}
	return strings.ToLower(enc)
}

// AlgToJWA maps our string algorithm to the jwx jwa enum.
func AlgToJWA(a kcrypto.Algorithm) (jwa.SignatureAlgorithm, error) {
	switch a {
	case kcrypto.AlgRS256:
		return jwa.RS256, nil
	case kcrypto.AlgES256:
		return jwa.ES256, nil
	case kcrypto.AlgEdDSA:
		return jwa.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported alg %q", a)
	}
}
