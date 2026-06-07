// Package observability owns keyforge's Prometheus metric definitions and
// the HTTP middleware that records request-level data.
//
// Every metric name MUST start with "keyforge_" so dashboards can be
// authored against a stable prefix; the lint test in metrics_test.go
// enforces this.
package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics bundles the keyforge Prometheus collectors. One process owns
// one Metrics instance; tests construct their own with a private
// Registry to avoid global-collector double-registration.
type Metrics struct {
	Registry *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	TokenIssuedTotal    *prometheus.CounterVec
	TokenRevokedTotal   *prometheus.CounterVec
	LoginAttemptsTotal  *prometheus.CounterVec
	DPoPProofFailures   *prometheus.CounterVec
	MTLSBindTotal       *prometheus.CounterVec
	JWKSRotationTotal   prometheus.Counter
	RateLimitDropsTotal *prometheus.CounterVec
	AuditEventsTotal    *prometheus.CounterVec
}

// New constructs a Metrics with a fresh registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		HTTPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_http_requests_total",
			Help: "Total HTTP requests by method, route, and status class.",
		}, []string{"method", "route", "status"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyforge_http_request_duration_seconds",
			Help:    "HTTP request latency by method and route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		TokenIssuedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_token_issued_total",
			Help: "OAuth tokens issued, labelled by grant_type and client_id.",
		}, []string{"grant_type", "client_id"}),
		TokenRevokedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_token_revoked_total",
			Help: "OAuth tokens revoked (RFC 7009 or via reuse detection).",
		}, []string{"reason"}),
		LoginAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_login_attempts_total",
			Help: "Browser-flow login attempts by result (success|fail|locked).",
		}, []string{"result"}),
		DPoPProofFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_dpop_proof_failures_total",
			Help: "DPoP proof validation failures by reason.",
		}, []string{"reason"}),
		MTLSBindTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_mtls_bind_total",
			Help: "Access tokens bound to a TLS client certificate.",
		}, []string{"result"}),
		JWKSRotationTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyforge_jwks_rotation_total",
			Help: "JWKS key rotations performed.",
		}),
		RateLimitDropsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_rate_limit_drops_total",
			Help: "Requests dropped by the rate limiter.",
		}, []string{"endpoint"}),
		AuditEventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyforge_audit_events_total",
			Help: "Audit events recorded by action.",
		}, []string{"action"}),
	}
	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.TokenIssuedTotal,
		m.TokenRevokedTotal,
		m.LoginAttemptsTotal,
		m.DPoPProofFailures,
		m.MTLSBindTotal,
		m.JWKSRotationTotal,
		m.RateLimitDropsTotal,
		m.AuditEventsTotal,
	)
	return m
}

// Handler returns the /metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}

// HTTPMiddleware records per-request metrics. Pair with chi.Router to
// get the route template as the label instead of the full URL.
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		route := r.URL.Path // chi-aware callers can override via context
		m.HTTPRequestsTotal.WithLabelValues(r.Method, route, statusClass(rw.status)).Inc()
		m.HTTPRequestDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func statusClass(s int) string {
	if s == 0 {
		return "0xx"
	}
	return strconv.Itoa(s/100) + "xx"
}
