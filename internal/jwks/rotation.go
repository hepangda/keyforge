package jwks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	kcrypto "github.com/hepangda/keyforge/internal/crypto"
)

// Rotator periodically rotates the active signing key once it exceeds
// rotateAfter age, then sweeps rotated keys past retainAfterRotate into
// retirement and deletes retired keys older than gracePeriod.
type Rotator struct {
	store             Store
	clk               Clock
	logger            *slog.Logger
	defaultAlg        kcrypto.Algorithm
	rotateAfter       time.Duration
	retainAfterRotate time.Duration
	gracePeriod       time.Duration
	interval          time.Duration
	tenantIDs         []uuid.UUID // empty == global scope (uuid.Nil)
}

// RotatorConfig configures a Rotator.
type RotatorConfig struct {
	Store             Store
	Clock             Clock
	Logger            *slog.Logger
	DefaultAlg        kcrypto.Algorithm
	RotateAfter       time.Duration
	RetainAfterRotate time.Duration
	GracePeriod       time.Duration
	Interval          time.Duration
	TenantIDs         []uuid.UUID
}

// NewRotator validates the config and returns a ready-to-run Rotator.
func NewRotator(cfg RotatorConfig) (*Rotator, error) {
	if cfg.Store == nil {
		return nil, errors.New("rotator: store required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock()
	}
	if cfg.DefaultAlg == "" {
		cfg.DefaultAlg = kcrypto.AlgRS256
	}
	if cfg.RotateAfter <= 0 {
		return nil, errors.New("rotator: RotateAfter must be > 0")
	}
	if cfg.RetainAfterRotate < 0 {
		return nil, errors.New("rotator: RetainAfterRotate must be >= 0")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	if cfg.GracePeriod <= 0 {
		// keep retired keys around for one rotation cycle before deleting
		cfg.GracePeriod = cfg.RetainAfterRotate
	}
	scopes := cfg.TenantIDs
	if len(scopes) == 0 {
		scopes = []uuid.UUID{uuid.Nil}
	}
	return &Rotator{
		store:             cfg.Store,
		clk:               cfg.Clock,
		logger:            cfg.Logger,
		defaultAlg:        cfg.DefaultAlg,
		rotateAfter:       cfg.RotateAfter,
		retainAfterRotate: cfg.RetainAfterRotate,
		gracePeriod:       cfg.GracePeriod,
		interval:          cfg.Interval,
		tenantIDs:         scopes,
	}, nil
}

// Run blocks until ctx is cancelled. On each tick it runs one Step.
func (r *Rotator) Run(ctx context.Context) error {
	if err := r.Step(ctx); err != nil {
		r.logger.Warn("jwks initial step failed", slog.Any("error", err))
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.Step(ctx); err != nil {
				r.logger.Warn("jwks rotation step failed", slog.Any("error", err))
			}
		}
	}
}

// Step performs one cycle: ensure an active key exists for each tenant scope,
// rotate any that have aged out, then sweep rotated/retired keys.
func (r *Rotator) Step(ctx context.Context) error {
	now := r.clk.Now()
	for _, tid := range r.tenantIDs {
		k, err := r.store.EnsureActive(ctx, tid, r.defaultAlg, UseSig)
		if err != nil {
			return fmt.Errorf("ensure active (tenant %s): %w", tid, err)
		}
		age := now.Sub(k.CreatedAt)
		if age >= r.rotateAfter {
			r.logger.Info(
				"rotating jwks key",
				slog.String("kid", k.KID),
				slog.String("alg", string(k.Alg)),
				slog.Duration("age", age),
				slog.String("tenant_id", tid.String()),
			)
			if _, err := r.store.Rotate(ctx, tid, r.defaultAlg, UseSig); err != nil {
				return fmt.Errorf("rotate (tenant %s): %w", tid, err)
			}
		}
	}
	if err := r.store.Sweep(ctx, r.retainAfterRotate, r.retainAfterRotate+r.gracePeriod); err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	return nil
}
