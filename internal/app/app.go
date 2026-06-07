// Package app composes keyforge's subsystems into a runnable application.
//
// The composition root constructs every concrete dependency, wires them
// together, and starts the public and admin HTTP servers under an errgroup.
// Lifecycle stops cleanly on context cancellation (typically SIGINT/SIGTERM).
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/sync/errgroup"

	"github.com/hepangda/keyforge/internal/config"
	"github.com/hepangda/keyforge/internal/httpx"
	"github.com/hepangda/keyforge/internal/httpx/spa"
	"github.com/hepangda/keyforge/internal/logging"
	"github.com/hepangda/keyforge/internal/observability"
	"github.com/hepangda/keyforge/pkg/version"
)

// App is the top-level keyforge application.
type App struct {
	cfg    config.Config
	logger *slog.Logger
	health *httpx.HealthHandler
	public *httpx.Server
	admin  *httpx.Server
}

// New constructs an App from a validated configuration. It does not open any
// network sockets; call Run to begin serving.
func New(_ context.Context, cfg config.Config) (*App, error) {
	logger := logging.New(logging.Options{
		Level:  logging.ParseLevel(cfg.Logging.Level),
		Format: cfg.Logging.Format,
		Source: cfg.Logging.Source,
	})
	logger.Info(
		"keyforge starting",
		slog.String("version", version.Version),
		slog.String("issuer", cfg.OIDC.Issuer),
	)

	health := httpx.NewHealthHandler()
	health.AddLiveness(httpx.ProbeFunc{N: "self", F: func(context.Context) error { return nil }})

	trustedCIDRs, err := httpx.ParseCIDRs(cfg.Security.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("parse trusted_proxies: %w", err)
	}

	metrics := observability.New()
	publicRouter := buildRouter(logger, health, trustedCIDRs, false, metrics)
	adminRouter := buildRouter(logger, health, trustedCIDRs, true, nil)

	// /metrics belongs on the admin listener so operational counters
	// never leak to the public surface.
	if r, ok := adminRouter.(chi.Router); ok {
		r.Handle("/metrics", metrics.Handler())
	}

	// Wire the OAuth + portal + admin handlers onto the routers. This
	// is best-effort: failures log and continue, leaving /healthz alive
	// for operator inspection.
	if pr, ok := publicRouter.(chi.Router); ok {
		if ar, ok := adminRouter.(chi.Router); ok {
			if err := wireOAuth(context.Background(), cfg, logger, pr, ar); err != nil {
				logger.Warn("wireOAuth returned error", slog.Any("error", err))
			}
		}
	}

	// SPA mount: best-effort. If web/dist is missing (rare; the stub
	// index.html ships in the repo) we log and continue, since the OAuth
	// surface is the load-bearing part of the binary.
	if spaH, err := spa.New(); err != nil {
		logger.Warn("SPA bundle unavailable", slog.Any("error", err))
	} else if r, ok := publicRouter.(chi.Router); ok {
		r.Handle("/portal", spaH)
		r.Handle("/portal/*", spaH)
		r.Handle("/admin", spaH)
		r.Handle("/admin/*", spaH)
		r.Handle("/assets/*", spaH)
	}

	publicSrv := httpx.NewServer(httpx.Config{
		Name:              "public",
		Addr:              cfg.Server.Addr,
		Handler:           otelhttp.NewHandler(publicRouter, "public"),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}, logger)

	adminSrv := httpx.NewServer(httpx.Config{
		Name:              "admin",
		Addr:              cfg.Server.AdminAddr,
		Handler:           otelhttp.NewHandler(adminRouter, "admin"),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}, logger)

	return &App{
		cfg:    cfg,
		logger: logger,
		health: health,
		public: publicSrv,
		admin:  adminSrv,
	}, nil
}

// Run blocks until ctx is cancelled or any subsystem errors. All servers
// receive a graceful shutdown bounded by cfg.Server.ShutdownTimeout.
func (a *App) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.public.Run(ctx, a.cfg.Server.ShutdownTimeout) })
	g.Go(func() error { return a.admin.Run(ctx, a.cfg.Server.ShutdownTimeout) })
	if err := g.Wait(); err != nil {
		a.logger.Error("keyforge stopped with error", slog.Any("error", err))
		return err
	}
	a.logger.Info("keyforge stopped cleanly")
	return nil
}

// Health exposes the health handler so tests or background workers can
// register additional probes.
func (a *App) Health() *httpx.HealthHandler { return a.health }

func buildRouter(logger *slog.Logger, health *httpx.HealthHandler, trusted []*net.IPNet, isAdmin bool, metrics *observability.Metrics) http.Handler {
	r := chi.NewRouter()
	r.Use(httpx.RequestID)
	r.Use(httpx.RealIP(trusted))
	r.Use(httpx.AccessLog(logger))
	r.Use(httpx.Recover(logger))
	r.Use(httpx.SecurityHeaders)
	if metrics != nil {
		r.Use(metrics.HTTPMiddleware)
	}

	r.Get("/healthz", health.Live)
	r.Get("/readyz", health.Ready)
	r.Get("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"version":%q,"admin":%t}`, version.Version, isAdmin)
	})
	return r
}
