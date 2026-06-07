// Package postgres also provides a migration runner that applies the embedded
// SQL files via golang-migrate.

package postgres

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migrate_pg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hepangda/keyforge/migrations"
)

// Migrate applies all pending up migrations from the embedded migrations FS.
// It opens a fresh database/sql connection from the pool's config and closes
// it on return.
func Migrate(pool *pgxpool.Pool) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}
	connCfg := pool.Config().ConnConfig.Copy()
	db := stdlib.OpenDB(*connCfg)
	defer func() { _ = db.Close() }()

	drv, err := migrate_pg.WithInstance(db, &migrate_pg.Config{})
	if err != nil {
		return fmt.Errorf("postgres driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", drv)
	if err != nil {
		return fmt.Errorf("new migrator: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
