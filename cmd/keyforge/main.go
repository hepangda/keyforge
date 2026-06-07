// Command keyforge is the keyforge OAuth 2.1 / OIDC authorization server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hepangda/keyforge/internal/app"
	"github.com/hepangda/keyforge/internal/config"
	"github.com/hepangda/keyforge/pkg/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		configPath  = flag.String("config", "", "Path to YAML config file (env vars KEYFORGE_* still apply)")
		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("keyforge", version.Version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build app:", err)
		return 1
	}

	if err := a.Run(ctx); err != nil {
		slog.Error("keyforge exited with error", slog.Any("error", err))
		return 1
	}
	return 0
}
