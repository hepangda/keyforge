package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// TxRunner executes a function within a database transaction with the given
// isolation level. The function receives a sqlc Queries bound to the
// transaction; if the function returns an error the transaction is rolled
// back, otherwise it is committed.
type TxRunner struct {
	pool *pgxpool.Pool
}

// NewTxRunner wraps a *pgxpool.Pool.
func NewTxRunner(pool *pgxpool.Pool) *TxRunner { return &TxRunner{pool: pool} }

// Iso is the transaction isolation level.
type Iso = pgx.TxIsoLevel

// Re-exported isolation levels for callers that do not want to import pgx
// directly.
const (
	ReadCommitted Iso = pgx.ReadCommitted
	Serializable  Iso = pgx.Serializable
)

// WithTx runs fn inside a transaction at the given isolation level.
func (r *TxRunner) WithTx(ctx context.Context, iso Iso, fn func(q *db.Queries) error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	q := db.New(tx)
	if err := fn(q); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
