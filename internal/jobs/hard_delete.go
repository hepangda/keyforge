// Package jobs houses background workers that run alongside the HTTP
// servers. They are deliberately tiny — one goroutine each, ticker-paced
// — so the composition root in internal/app can start/stop them under
// the same errgroup that owns the network listeners.
package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// HardDeleteWorker periodically purges users whose soft-delete has aged
// past the retention window. The plan's choice of 30 days is the default;
// operators can override via config.
type HardDeleteWorker struct {
	q         *db.Queries
	retention time.Duration
	interval  time.Duration
	logger    *slog.Logger
}

// NewHardDeleteWorker constructs the worker. Zero values get sensible
// defaults (30d retention, 1h sweep interval).
func NewHardDeleteWorker(q *db.Queries, retention, interval time.Duration, logger *slog.Logger) *HardDeleteWorker {
	if retention == 0 {
		retention = 30 * 24 * time.Hour
	}
	if interval == 0 {
		interval = time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &HardDeleteWorker{q: q, retention: retention, interval: interval, logger: logger}
}

// Run blocks until ctx is cancelled.
func (w *HardDeleteWorker) Run(ctx context.Context) error {
	w.tick(ctx) // sweep once on boot so a long-running process doesn't wait an hour
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *HardDeleteWorker) tick(ctx context.Context) {
	cutoff := time.Now().Add(-w.retention)
	n, err := w.q.HardDeleteExpiredUsers(ctx, pgtype.Timestamptz{Time: cutoff, Valid: true})
	if err != nil {
		w.logger.Warn("hard-delete sweep failed", slog.Any("error", err))
		return
	}
	if n > 0 {
		w.logger.Info("hard-deleted soft-deleted users",
			slog.Int64("count", n),
			slog.Time("cutoff", cutoff))
	}
}
