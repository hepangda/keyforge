// Package logging configures keyforge's structured logger.
//
// Logs are emitted via log/slog as JSON to stdout in production and as text
// in development. A custom ReplaceAttr scrubs values whose keys look like
// secrets (password, token, code, refresh_token, id_token, private_*, ...)
// so that production logs cannot leak credentials.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Redacted is the placeholder substituted for any redacted attribute value.
const Redacted = "[REDACTED]"

// sensitiveExact contains attribute keys that must always be redacted.
var sensitiveExact = map[string]struct{}{
	"password":                {},
	"passwd":                  {},
	"secret":                  {},
	"client_secret":           {},
	"token":                   {},
	"access_token":            {},
	"refresh_token":           {},
	"id_token":                {},
	"code":                    {},
	"code_verifier":           {},
	"assertion":               {},
	"client_assertion":        {},
	"authorization":           {},
	"cookie":                  {},
	"set-cookie":              {},
	"dpop":                    {},
	"x-forwarded-client-cert": {},
}

// sensitivePrefixes contains attribute key prefixes that imply redaction.
var sensitivePrefixes = []string{
	"private_",
	"secret_",
	"password_",
	"token_",
}

// Options configures the slog handler.
type Options struct {
	Level  slog.Level
	Format string // "json" or "text"
	Source bool
	Writer io.Writer
}

// New builds a *slog.Logger that redacts sensitive attributes.
func New(opts Options) *slog.Logger {
	if opts.Writer == nil {
		opts.Writer = os.Stdout
	}
	ho := &slog.HandlerOptions{
		Level:       opts.Level,
		AddSource:   opts.Source,
		ReplaceAttr: redact,
	}
	var h slog.Handler
	switch strings.ToLower(opts.Format) {
	case "text":
		h = slog.NewTextHandler(opts.Writer, ho)
	default:
		h = slog.NewJSONHandler(opts.Writer, ho)
	}
	return slog.New(h)
}

// ParseLevel converts "debug"/"info"/"warn"/"error" into a slog.Level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Key == "" {
		return a
	}
	lc := strings.ToLower(a.Key)
	if _, ok := sensitiveExact[lc]; ok {
		return slog.String(a.Key, Redacted)
	}
	for _, p := range sensitivePrefixes {
		if strings.HasPrefix(lc, p) {
			return slog.String(a.Key, Redacted)
		}
	}
	return a
}
