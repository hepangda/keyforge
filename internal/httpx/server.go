// Package httpx hosts keyforge's HTTP plumbing: server lifecycle, common
// middleware, health/readiness endpoints, and the SPA mount helper.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Server wraps a single *http.Server with a slog logger and a graceful
// shutdown helper.
type Server struct {
	name   string
	srv    *http.Server
	logger *slog.Logger
}

// Config configures a single Server.
type Config struct {
	Name              string
	Addr              string
	Handler           http.Handler
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	TLSConfig         *TLSConfig
}

// TLSConfig configures optional TLS termination for a Server.
type TLSConfig struct {
	CertFile      string
	KeyFile       string
	ClientCAFile  string
	RequireClient bool
}

// NewServer constructs a Server using sane defaults.
func NewServer(cfg Config, logger *slog.Logger) *Server {
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           cfg.Handler,
		ReadHeaderTimeout: orDefault(cfg.ReadHeaderTimeout, 10*time.Second),
		IdleTimeout:       orDefault(cfg.IdleTimeout, 120*time.Second),
	}
	return &Server{name: cfg.Name, srv: srv, logger: logger}
}

// Run blocks listening on the configured address until ctx is cancelled or a
// fatal error occurs. ctx cancellation triggers a graceful shutdown bounded
// by shutdownTimeout.
func (s *Server) Run(ctx context.Context, shutdownTimeout time.Duration) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("listen %s on %s: %w", s.name, s.srv.Addr, err)
	}
	s.logger.Info(
		"http server listening",
		slog.String("server", s.name),
		slog.String("addr", ln.Addr().String()),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		s.logger.Info("http server shutting down", slog.String("server", s.name))
		if err := s.srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("shutdown %s: %w", s.name, err)
		}
		return nil
	}
}

// Addr returns the configured listen address (useful in tests that pass :0).
func (s *Server) Addr() string { return s.srv.Addr }

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
