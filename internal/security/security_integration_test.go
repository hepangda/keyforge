//go:build integration

package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/security/lockout"
	"github.com/hepangda/keyforge/internal/security/ratelimit"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/testsupport"
)

func TestMemoryBucketAllowsBurstThenLimits(t *testing.T) {
	l := ratelimit.NewMemory(ratelimit.Policy{Capacity: 3, RefillRate: 0.5})
	hits := 0
	for i := 0; i < 10; i++ {
		if l.Allow(context.Background(), "test", "key1").OK {
			hits++
		}
	}
	if hits < 3 || hits > 4 { // capacity + maybe one refill within the loop
		t.Fatalf("expected ~3 allows, got %d", hits)
	}
}

func TestPostgresBucketSharedAcrossCallers(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)
	l := ratelimit.NewPostgres(q, ratelimit.Policy{Capacity: 2, RefillRate: 0.1})

	if !l.Allow(ctx, "ep", "k").OK {
		t.Fatal("first request should be allowed")
	}
	if !l.Allow(ctx, "ep", "k").OK {
		t.Fatal("second request should be allowed")
	}
	if l.Allow(ctx, "ep", "k").OK {
		t.Fatal("third request should be denied")
	}
}

func TestLockoutAfterThreshold(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)
	tenant, _ := q.CreateTenant(ctx, db.CreateTenantParams{
		Slug: "lo", DisplayName: "Lockout", Issuer: "https://lo.test",
	})

	s := lockout.New(q, lockout.Policy{
		Threshold: 3, Window: time.Minute, Duration: time.Minute,
	})
	email := "victim@lo.test"

	// First three failures stay below the threshold (lockout fires on the 3rd).
	for i := 0; i < 3; i++ {
		if err := s.RecordFailure(ctx, tenant.ID, email, "1.2.3.4"); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	_, locked, err := s.IsLocked(ctx, tenant.ID, email)
	if err != nil {
		t.Fatalf("is locked: %v", err)
	}
	if !locked {
		t.Fatalf("expected lockout after %d failures", 3)
	}

	// Admin unlock clears the lock.
	if err := s.Unlock(ctx, tenant.ID, email); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	_, locked, _ = s.IsLocked(ctx, tenant.ID, email)
	if locked {
		t.Fatalf("expected unlock to clear lockout")
	}

	// Successful login wipes the failure history.
	if err := s.ClearFailures(ctx, tenant.ID, email); err != nil {
		t.Fatalf("clear: %v", err)
	}

	// And different (tenant, email) pairs are independent.
	another := uuid.MustParse(tenant.ID.String())
	_, locked2, _ := s.IsLocked(ctx, another, "other@lo.test")
	if locked2 {
		t.Fatalf("unrelated email should not be locked")
	}
}

func TestLockoutHashesEmailWithTenant(t *testing.T) {
	a := uuid.New()
	b := uuid.New()
	if string(lockout.HashEmail(a, "x@y")) == string(lockout.HashEmail(b, "x@y")) {
		t.Fatal("same email + different tenant must hash differently")
	}
}
