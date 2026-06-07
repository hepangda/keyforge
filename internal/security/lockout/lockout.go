// Package lockout implements per-account brute-force protection.
//
// Failures are keyed on (tenant_id, email_hash) so we don't enumerate
// users. After Threshold failures within Window the account is locked
// out for the configured Duration; admin Unlock removes the row.
package lockout

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Policy configures the lockout behaviour.
type Policy struct {
	Threshold int           // number of failures that triggers a lockout
	Window    time.Duration // window the failures are counted over
	Duration  time.Duration // how long the lockout stays in place
}

// DefaultPolicy mirrors the plan's commitments: 8 failures in 15m,
// 15-minute lockout.
func DefaultPolicy() Policy {
	return Policy{Threshold: 8, Window: 15 * time.Minute, Duration: 15 * time.Minute}
}

// Service tracks failures and enforces lockouts.
type Service struct {
	q      *db.Queries
	policy Policy
}

// New constructs a Service.
func New(q *db.Queries, p Policy) *Service {
	if p.Threshold == 0 {
		p = DefaultPolicy()
	}
	return &Service{q: q, policy: p}
}

// HashEmail returns the bcrypt-style hash we store in login_failures.
// Using SHA-256 + tenant_id binding keeps the storage cheap while
// preventing trivial user enumeration from a leaked DB dump.
func HashEmail(tenantID uuid.UUID, email string) []byte {
	h := sha256.New()
	h.Write(tenantID[:])
	h.Write([]byte{':'})
	h.Write([]byte(email))
	return h.Sum(nil)
}

// IsLocked reports whether the (tenant, email) pair is currently locked.
// Returns the unlock_at timestamp when locked.
func (s *Service) IsLocked(ctx context.Context, tenantID uuid.UUID, email string) (time.Time, bool, error) {
	row, err := s.q.GetActiveLockout(ctx, db.GetActiveLockoutParams{
		TenantID:  tenantID,
		EmailHash: HashEmail(tenantID, email),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	return row.UnlockAt, true, nil
}

// RecordFailure records one bad login and applies a lockout when the
// running count crosses Threshold within Window.
func (s *Service) RecordFailure(ctx context.Context, tenantID uuid.UUID, email, ip string) error {
	hash := HashEmail(tenantID, email)
	ipText := pgtype.Text{}
	if ip != "" {
		ipText = pgtype.Text{String: ip, Valid: true}
	}
	if err := s.q.RecordLoginFailure(ctx, db.RecordLoginFailureParams{
		TenantID:  tenantID,
		EmailHash: hash,
		Ip:        ipText,
	}); err != nil {
		return err
	}
	since := time.Now().Add(-s.policy.Window)
	n, err := s.q.CountRecentLoginFailures(ctx, db.CountRecentLoginFailuresParams{
		TenantID:   tenantID,
		EmailHash:  hash,
		OccurredAt: since,
	})
	if err != nil {
		return err
	}
	if int(n) >= s.policy.Threshold {
		return s.q.UpsertLockout(ctx, db.UpsertLockoutParams{
			TenantID:  tenantID,
			EmailHash: hash,
			UnlockAt:  time.Now().Add(s.policy.Duration),
			Reason:    "too_many_failures",
		})
	}
	return nil
}

// ClearFailures wipes the failure history on a successful login so the
// next failure window starts fresh.
func (s *Service) ClearFailures(ctx context.Context, tenantID uuid.UUID, email string) error {
	return s.q.ClearLoginFailures(ctx, db.ClearLoginFailuresParams{
		TenantID:  tenantID,
		EmailHash: HashEmail(tenantID, email),
	})
}

// Unlock removes an active lockout. Used by the admin "unlock" action.
func (s *Service) Unlock(ctx context.Context, tenantID uuid.UUID, email string) error {
	return s.q.DeleteLockout(ctx, db.DeleteLockoutParams{
		TenantID:  tenantID,
		EmailHash: HashEmail(tenantID, email),
	})
}
