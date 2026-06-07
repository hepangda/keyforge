package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by recovery codes.
var (
	ErrRecoveryNotFound = errors.New("mfa: recovery code not found")
	ErrRecoveryConsumed = errors.New("mfa: recovery code already used")
)

// RecoveryCodeCount is the number of fresh recovery codes minted per call.
const RecoveryCodeCount = 10

// RecoveryFactor manages the per-user single-use recovery code list.
type RecoveryFactor struct {
	q *db.Queries
}

// NewRecovery constructs the factor.
func NewRecovery(q *db.Queries) *RecoveryFactor { return &RecoveryFactor{q: q} }

// Generate mints RecoveryCodeCount fresh codes, replaces any existing
// codes the user had, and returns the plaintext codes EXACTLY ONCE for
// display. Each code is 10 base32 characters formatted as XXXXX-XXXXX.
func (r *RecoveryFactor) Generate(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	if err := r.q.DeleteRecoveryCodesForUser(ctx,
		db.DeleteRecoveryCodesForUserParams{TenantID: tenantID, UserID: userID}); err != nil {
		return nil, fmt.Errorf("clear recovery codes: %w", err)
	}
	codes := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(normalize(code)), 12)
		if err != nil {
			return nil, fmt.Errorf("hash recovery code: %w", err)
		}
		if err := r.q.InsertRecoveryCode(ctx, db.InsertRecoveryCodeParams{
			TenantID: tenantID,
			UserID:   userID,
			CodeHash: string(hash),
		}); err != nil {
			return nil, fmt.Errorf("insert recovery code: %w", err)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// Verify consumes a presented recovery code: it scans the user's hashed
// codes for a bcrypt match, atomically marks the matched row as used, and
// returns nil. Failure modes: ErrRecoveryNotFound (no match) or any DB
// error.
//
// Linear scan is intentional: bcrypt hashes are non-deterministic so we
// cannot index lookup by hash. RecoveryCodeCount keeps the fanout bounded.
func (r *RecoveryFactor) Verify(ctx context.Context, tenantID, userID uuid.UUID, presented string) error {
	rows, err := r.list(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	norm := normalize(presented)
	for _, row := range rows {
		if bcrypt.CompareHashAndPassword([]byte(row.CodeHash), []byte(norm)) != nil {
			continue
		}
		_, cerr := r.q.ConsumeRecoveryCode(ctx, db.ConsumeRecoveryCodeParams{
			TenantID: tenantID, UserID: userID, CodeHash: row.CodeHash,
		})
		if cerr != nil {
			if errors.Is(cerr, pgx.ErrNoRows) {
				return ErrRecoveryConsumed
			}
			return fmt.Errorf("consume recovery code: %w", cerr)
		}
		return nil
	}
	return ErrRecoveryNotFound
}

// Remaining returns the number of unused codes still on file.
func (r *RecoveryFactor) Remaining(ctx context.Context, tenantID, userID uuid.UUID) (int64, error) {
	return r.q.CountActiveRecoveryCodes(ctx,
		db.CountActiveRecoveryCodesParams{TenantID: tenantID, UserID: userID})
}

func (r *RecoveryFactor) list(ctx context.Context, tenantID, userID uuid.UUID) ([]*db.UserRecoveryCode, error) {
	return r.q.ListActiveRecoveryCodes(ctx,
		db.ListActiveRecoveryCodesParams{TenantID: tenantID, UserID: userID})
}

// newRecoveryCode mints a 10-char base32 string formatted as XXXXX-XXXXX.
func newRecoveryCode() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	enc := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b[:]), "="))
	enc = (enc + "0000000000")[:10]
	return enc[:5] + "-" + enc[5:], nil
}

// normalize strips spaces, dashes, and lower-cases so the user can type
// the code with or without the visual separator.
func normalize(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(s))
}
