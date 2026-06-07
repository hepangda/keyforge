// Package ratelimit implements keyforge's request-rate enforcement. Two
// backends ship today:
//
//   - MemoryTokenBucket: a per-process golang.org/x/time/rate bucket
//     keyed on (endpoint, key). Fast, no DB round-trip; appropriate for
//     single-replica deployments.
//   - PostgresLeakyBucket: a shared bucket persisted in rate_buckets so
//     multiple replicas converge on the same view.
//
// Both implement Limiter so the surrounding HTTP middleware doesn't care
// which backend is wired up.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Limiter is the persistence-agnostic rate-limit contract.
type Limiter interface {
	Allow(ctx context.Context, endpoint, key string) Decision
}

// Decision summarises the outcome of an Allow call.
type Decision struct {
	OK         bool
	RetryAfter time.Duration
}

// Policy configures the bucket parameters: capacity (max burst) and
// refill rate per second.
type Policy struct {
	Capacity   int
	RefillRate float64 // tokens added per second
}

// MemoryTokenBucket is a per-process golang.org/x/time/rate-backed limiter.
type MemoryTokenBucket struct {
	policy Policy
	mu     sync.Mutex
	cache  map[string]*rate.Limiter
}

// NewMemory constructs a MemoryTokenBucket.
func NewMemory(p Policy) *MemoryTokenBucket {
	return &MemoryTokenBucket{policy: p, cache: map[string]*rate.Limiter{}}
}

// Allow implements Limiter.
func (m *MemoryTokenBucket) Allow(_ context.Context, endpoint, key string) Decision {
	id := endpoint + "|" + key
	m.mu.Lock()
	l, ok := m.cache[id]
	if !ok {
		l = rate.NewLimiter(rate.Limit(m.policy.RefillRate), m.policy.Capacity)
		m.cache[id] = l
	}
	m.mu.Unlock()
	if l.Allow() {
		return Decision{OK: true}
	}
	// Compute the next acceptable interval as the inverse of the refill
	// rate so the Retry-After hint is meaningful even though x/time/rate
	// doesn't expose the next-available time.
	wait := time.Second
	if m.policy.RefillRate > 0 {
		wait = time.Duration(float64(time.Second) / m.policy.RefillRate)
	}
	return Decision{OK: false, RetryAfter: wait}
}

// PostgresLeakyBucket is a shared limiter persisted in rate_buckets.
// Each Allow run drains the bucket by (now - last_updated) * rate, then
// adds one. If level > capacity the request is rejected.
type PostgresLeakyBucket struct {
	q      *db.Queries
	policy Policy
}

// NewPostgres constructs a PostgresLeakyBucket.
func NewPostgres(q *db.Queries, p Policy) *PostgresLeakyBucket {
	return &PostgresLeakyBucket{q: q, policy: p}
}

// Allow implements Limiter.
func (p *PostgresLeakyBucket) Allow(ctx context.Context, endpoint, key string) Decision {
	now := time.Now().UTC()
	row, err := p.q.GetRateBucket(ctx, db.GetRateBucketParams{Endpoint: endpoint, Key: key})
	level := 0.0
	if err == nil {
		drain := now.Sub(row.UpdatedAt).Seconds() * p.policy.RefillRate
		level = row.Level - drain
		if level < 0 {
			level = 0
		}
	}
	level++
	if level > float64(p.policy.Capacity) {
		return Decision{OK: false, RetryAfter: time.Second}
	}
	if _, err := p.q.UpsertRateBucket(ctx, db.UpsertRateBucketParams{
		Endpoint: endpoint, Key: key, Level: level,
	}); err != nil {
		// Fail open on persistence errors: better to allow the request
		// than to break the entire endpoint.
		return Decision{OK: true}
	}
	return Decision{OK: true}
}

// Middleware mounts a limiter on an HTTP handler. keyFn extracts the
// rate-limit key (client_id, IP, email hash, etc.) from the request.
func Middleware(l Limiter, endpoint string, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			d := l.Allow(r.Context(), endpoint, key)
			if !d.OK {
				w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
