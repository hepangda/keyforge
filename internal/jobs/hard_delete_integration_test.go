//go:build integration

package jobs_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/jobs"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/testsupport"
)

func TestHardDeleteRespectsRetention(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)
	q := db.New(fx.Pool)

	tenant, err := q.CreateTenant(ctx, db.CreateTenantParams{
		Slug: "hd", DisplayName: "HD", Issuer: "https://hd.test",
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	ctxT := postgres.ContextWithTenant(ctx, tenant.ID)

	old, err := q.CreateUser(ctxT, db.CreateUserParams{TenantID: tenant.ID, Email: "old@hd.test"})
	if err != nil {
		t.Fatalf("old user: %v", err)
	}
	young, err := q.CreateUser(ctxT, db.CreateUserParams{TenantID: tenant.ID, Email: "new@hd.test"})
	if err != nil {
		t.Fatalf("young user: %v", err)
	}
	// Backdate one beyond retention, leave the other fresh.
	if _, err := fx.Pool.Exec(ctx,
		`UPDATE users SET deleted_at = NOW() - INTERVAL '40 days' WHERE id = $1`, old.ID,
	); err != nil {
		t.Fatalf("backdate old: %v", err)
	}
	if _, err := fx.Pool.Exec(ctx,
		`UPDATE users SET deleted_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, young.ID,
	); err != nil {
		t.Fatalf("touch young: %v", err)
	}

	worker := jobs.NewHardDeleteWorker(q, 30*24*time.Hour, time.Hour,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Run is a long-lived loop. We let its boot-time tick fire, then
	// cancel.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = worker.Run(runCtx) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if exists := rowExists(t, ctx, fx, old.ID); exists {
		t.Fatalf("expected old user to be hard-deleted")
	}
	if exists := rowExists(t, ctx, fx, young.ID); !exists {
		t.Fatalf("expected young user to still exist")
	}
}

func rowExists(t *testing.T, ctx context.Context, fx *testsupport.PGFixture, id uuid.UUID) bool {
	t.Helper()
	var n int
	if err := fx.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n > 0
}
