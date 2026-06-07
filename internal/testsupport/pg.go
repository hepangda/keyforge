// Package testsupport contains helpers for tests that need real infrastructure
// (Postgres, etc.). The helpers are guarded by build tags so that ordinary
// `go test ./...` stays fast and offline; integration tests opt in with
// `-tags=integration`.
package testsupport

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/hepangda/keyforge/internal/storage/postgres"
)

// PGFixture is one running postgres container plus a pgxpool that has had all
// migrations applied. Tests should request a Truncate before each subtest to
// preserve isolation when they share a fixture via NewSharedPostgres.
type PGFixture struct {
	URL  string
	Pool *pgxpool.Pool
	// stop tears down the container; called from the t.Cleanup that created
	// the fixture.
	stop func()
}

// Stop terminates the underlying container and closes the pool.
func (f *PGFixture) Stop() {
	if f == nil {
		return
	}
	if f.Pool != nil {
		f.Pool.Close()
	}
	if f.stop != nil {
		f.stop()
	}
}

// Truncate resets every keyforge-owned table while leaving the schema intact.
// Use this between tests that share a fixture to keep them independent.
func (f *PGFixture) Truncate(ctx context.Context, t testing.TB) {
	t.Helper()
	const stmt = `TRUNCATE TABLE
		jwks_keys,
		client_redirect_uris,
		clients,
		user_credentials,
		users,
		tenants
	RESTART IDENTITY CASCADE`
	if _, err := f.Pool.Exec(ctx, stmt); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// NewPostgres boots a fresh Postgres container for the calling test, applies
// migrations, and registers cleanup. The container is dedicated to this test
// and dies with it; for shared-container speed use SharedPostgres.
func NewPostgres(ctx context.Context, t testing.TB) *PGFixture {
	t.Helper()

	container, err := tcpostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("keyforge"),
		tcpostgres.WithUsername("keyforge"),
		tcpostgres.WithPassword("keyforge"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("pgx"),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	url, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("container connection string: %v", err)
	}

	pool, err := openWithRetry(ctx, url, 30*time.Second)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	if err := postgres.Migrate(pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}

	fx := &PGFixture{
		URL:  url,
		Pool: pool,
		stop: func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			//nolint:contextcheck // cleanup deliberately uses a fresh context; the
			// test's context is typically already cancelled by the time t.Cleanup
			// runs.
			_ = container.Terminate(stopCtx)
		},
	}
	t.Cleanup(fx.Stop)
	return fx
}

var (
	sharedOnce sync.Once
	sharedFx   *PGFixture
	sharedErr  error
)

// SharedPostgres returns a process-wide singleton fixture, lazily created on
// the first call. Use this for hot test suites that should not pay the
// container-startup cost per test; call Truncate at the top of each subtest.
//
// The fixture is intentionally NOT cleaned up via t.Cleanup; it survives until
// the test binary exits.
func SharedPostgres(ctx context.Context, t testing.TB) *PGFixture {
	t.Helper()
	sharedOnce.Do(func() {
		sharedFx = NewPostgres(ctx, t)
		// drop the t.Cleanup the per-call helper added; we don't want it
		// killing the shared fixture when this one test ends.
		sharedFx.stop = func() {} //nolint:gocritic
	})
	if sharedErr != nil {
		t.Fatalf("shared postgres unavailable: %v", sharedErr)
	}
	return sharedFx
}

func openWithRetry(ctx context.Context, url string, total time.Duration) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(total)
	var lastErr error
	for time.Now().Before(deadline) {
		pool, err := pgxpool.New(ctx, url)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = pool.Ping(pingCtx)
			cancel()
			if err == nil {
				return pool, nil
			}
			pool.Close()
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("postgres not ready after %v: %w", total, lastErr)
}
