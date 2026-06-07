// Package postgres provides keyforge's PostgreSQL connection pool, transaction
// helper, and multi-tenant context plumbing.
package postgres

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/config"
)

// NewPool opens a pgxpool against cfg.URL with OpenTelemetry tracing wired in,
// applies the connection limits from cfg, and PINGs once before returning.
func NewPool(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	pc.MaxConns = clampInt32(cfg.MaxOpenConns)
	pc.MinConns = clampInt32(cfg.MaxIdleConns)
	pc.MaxConnLifetime = cfg.ConnMaxLifetime
	pc.ConnConfig.Tracer = otelpgx.NewTracer()

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("open pgxpool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return pool, nil
}

// PingProbe returns a function that reports DB connectivity for /readyz.
func PingProbe(pool *pgxpool.Pool) func(context.Context) error {
	return func(ctx context.Context) error {
		return pool.Ping(ctx)
	}
}

// Querier abstracts the subset of pgx that both pools and transactions offer.
// sqlc-generated code accepts a pgx.Conn or pgxpool.Pool; this type narrows
// our handlers to those two without depending on the generated package.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// clampInt32 narrows an int (from config) to int32 with bounds checking.
// pgxpool uses int32 for MaxConns/MinConns; config-supplied negatives or
// values past math.MaxInt32 are clamped rather than silently overflowed.
func clampInt32(v int) int32 {
	switch {
	case v < 0:
		return 0
	case v > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(v)
	}
}
