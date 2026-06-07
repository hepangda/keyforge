package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// RequestIDHeader is the HTTP header carrying the per-request correlation ID.
const RequestIDHeader = "X-Request-Id"

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxRealIP
)

// RequestID is a chi-compatible middleware that ensures every request has a
// stable correlation ID. The ID is taken from RequestIDHeader if present,
// otherwise a 128-bit random hex string is generated. The chosen ID is set
// back on the response and made available via RequestIDFromContext.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext returns the request ID injected by RequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// RealIP records the originating client IP on the request context. If trusted
// proxies are configured and the immediate peer is in that set, the leftmost
// IP from X-Forwarded-For is trusted; otherwise the TCP remote address is
// used directly.
func RealIP(trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := remoteIP(r)
			if len(trustedCIDRs) > 0 && peerInTrusted(r, trustedCIDRs) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					parts := strings.Split(xff, ",")
					ip = strings.TrimSpace(parts[0])
				}
			}
			ctx := context.WithValue(r.Context(), ctxRealIP, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RealIPFromContext returns the client IP determined by RealIP.
func RealIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRealIP).(string)
	return v
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func peerInTrusted(r *http.Request, cidrs []*net.IPNet) bool {
	peer := net.ParseIP(remoteIP(r))
	if peer == nil {
		return false
	}
	for _, c := range cidrs {
		if c.Contains(peer) {
			return true
		}
	}
	return false
}

// ParseCIDRs converts string CIDRs into *net.IPNet, returning the first parse
// error encountered.
func ParseCIDRs(in []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// SecurityHeaders sets a baseline set of conservative response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

// AccessLog is a minimal slog-backed access logger. It is intentionally
// independent of chi/middleware.Logger so that tests do not depend on chi.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			logger.LogAttrs(
				r.Context(), slog.LevelInfo, "http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rw.status),
				slog.Int64("bytes", rw.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("ip", RealIPFromContext(r.Context())),
			)
		})
	}
}

// Recover converts panics into 500s and logs them through slog.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			defer func() {
				if rec := recover(); rec != nil {
					logger.LogAttrs(
						ctx, slog.LevelError, "panic recovered",
						slog.Any("panic", rec),
						slog.String("path", r.URL.Path),
						slog.String("request_id", RequestIDFromContext(ctx)),
					)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}
