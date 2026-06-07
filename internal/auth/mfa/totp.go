// Package mfa provides keyforge's multi-factor authentication factors:
//
//   - TOTP (RFC 6238) via pquerna/otp
//   - WebAuthn (FIDO2 / passkeys) via go-webauthn/webauthn
//   - 10-code single-use recovery codes
//
// All persistent secrets are stored encrypted under the same envelope
// helper the JWKS keyset uses (crypto.Envelope), so a database dump cannot
// be replayed without the KEK.
package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by the TOTP factor.
var (
	ErrTOTPNotEnrolled = errors.New("mfa: TOTP not enrolled for user")
	ErrTOTPNotVerified = errors.New("mfa: TOTP code did not verify")
	ErrTOTPReplay      = errors.New("mfa: TOTP code already used")
)

// TOTPFactor manages the per-user TOTP secret lifecycle.
type TOTPFactor struct {
	q         *db.Queries
	env       *kcrypto.Envelope
	issuer    string
	algorithm otp.Algorithm
	digits    otp.Digits
	period    uint
}

// NewTOTP constructs the factor.
func NewTOTP(q *db.Queries, env *kcrypto.Envelope, issuer string) *TOTPFactor {
	return &TOTPFactor{
		q:         q,
		env:       env,
		issuer:    issuer,
		algorithm: otp.AlgorithmSHA1,
		digits:    otp.DigitsSix,
		period:    30,
	}
}

// EnrollResult is what BeginEnroll returns to the user-portal page: an
// otpauth:// URL to render as a QR code plus the raw base32 secret for
// manual entry. The factor stays unconfirmed until ConfirmEnroll succeeds
// against a fresh code.
type EnrollResult struct {
	OTPAuthURL string
	Secret     string
}

// BeginEnroll generates a fresh secret, encrypts it under the KEK, and
// persists an unconfirmed user_mfa_totp row. The user must then submit a
// matching code via ConfirmEnroll for the factor to become active.
func (t *TOTPFactor) BeginEnroll(ctx context.Context, tenantID, userID uuid.UUID, accountLabel string) (*EnrollResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: accountLabel,
		Period:      t.period,
		Digits:      t.digits,
		Algorithm:   t.algorithm,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("totp generate: %w", err)
	}
	secret := key.Secret() // base32
	wrappedDEK, ct, err := t.env.SealWithDEK([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("seal totp secret: %w", err)
	}
	if err := t.q.UpsertUserTOTP(ctx, db.UpsertUserTOTPParams{
		UserID:           userID,
		TenantID:         tenantID,
		SecretCiphertext: ct,
		DEKCiphertext:    wrappedDEK,
		Algorithm:        t.algorithm.String(),
		Digits:           int32(t.digits.Length()), //nolint:gosec // 6 or 8
		PeriodSeconds:    int32(t.period),          //nolint:gosec // 30
	}); err != nil {
		return nil, fmt.Errorf("upsert totp: %w", err)
	}
	return &EnrollResult{OTPAuthURL: key.URL(), Secret: secret}, nil
}

// ConfirmEnroll verifies the user's first TOTP code; on success the row's
// confirmed_at is set and the factor becomes valid for subsequent logins.
func (t *TOTPFactor) ConfirmEnroll(ctx context.Context, tenantID, userID uuid.UUID, presented string) error {
	row, err := t.q.GetUserTOTP(ctx, db.GetUserTOTPParams{UserID: userID, TenantID: tenantID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTOTPNotEnrolled
		}
		return fmt.Errorf("load totp: %w", err)
	}
	secret, err := t.decryptSecret(row)
	if err != nil {
		return err
	}
	now := time.Now()
	if !totp.Validate(presented, secret) {
		return ErrTOTPNotVerified
	}
	counter := int64(now.Unix() / int64(t.period)) //nolint:gosec // period is 30, bounded
	return t.q.ConfirmUserTOTP(ctx, db.ConfirmUserTOTPParams{
		UserID:      userID,
		TenantID:    tenantID,
		LastCounter: pgtype.Int8{Int64: counter, Valid: true},
	})
}

// Verify is what the login flow calls during step-up. Returns nil iff the
// code is valid AND the counter hasn't been used before.
func (t *TOTPFactor) Verify(ctx context.Context, tenantID, userID uuid.UUID, presented string) error {
	row, err := t.q.GetUserTOTP(ctx, db.GetUserTOTPParams{UserID: userID, TenantID: tenantID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTOTPNotEnrolled
		}
		return fmt.Errorf("load totp: %w", err)
	}
	if !row.ConfirmedAt.Valid {
		return ErrTOTPNotEnrolled
	}
	secret, err := t.decryptSecret(row)
	if err != nil {
		return err
	}
	if !totp.Validate(presented, secret) {
		return ErrTOTPNotVerified
	}
	counter := int64(time.Now().Unix() / int64(t.period)) //nolint:gosec // period is 30, bounded
	if row.LastCounter.Valid && row.LastCounter.Int64 >= counter {
		return ErrTOTPReplay
	}
	return t.q.TouchUserTOTP(ctx, db.TouchUserTOTPParams{
		UserID:      userID,
		TenantID:    tenantID,
		LastCounter: pgtype.Int8{Int64: counter, Valid: true},
	})
}

// IsEnrolled reports whether the user has a confirmed TOTP factor.
func (t *TOTPFactor) IsEnrolled(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	row, err := t.q.GetUserTOTP(ctx, db.GetUserTOTPParams{UserID: userID, TenantID: tenantID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return row.ConfirmedAt.Valid, nil
}

// Remove deletes the user's TOTP factor.
func (t *TOTPFactor) Remove(ctx context.Context, tenantID, userID uuid.UUID) error {
	return t.q.DeleteUserTOTP(ctx, db.DeleteUserTOTPParams{UserID: userID, TenantID: tenantID})
}

func (t *TOTPFactor) decryptSecret(row *db.UserMfaTotp) (string, error) {
	plain, err := t.env.OpenWithDEK(row.DEKCiphertext, row.SecretCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt totp secret: %w", err)
	}
	return string(plain), nil
}
