// Package migrations embeds keyforge's SQL migration files so the binary can
// apply them directly via golang-migrate without an external mount.
//
// The migration directory is the authoritative source of truth; sqlc consumes
// it (via sqlc.yaml's schema: migrations) and tests mount it through an
// iofs source.
package migrations

import "embed"

// FS embeds every *.sql file in /migrations at compile time.
//
//go:embed *.sql
var FS embed.FS
