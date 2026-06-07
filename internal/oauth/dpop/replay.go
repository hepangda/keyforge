package dpop

import (
	"sync"
	"time"
)

// ReplayCache records DPoP jti values to detect replay within their
// freshness window.
type ReplayCache interface {
	// Seen records jti as consumed for at least ttl. Returns true iff the
	// jti was already present (i.e. this is a replay).
	Seen(jti string, ttl time.Duration) (bool, error)
}

// MemoryReplay is a small in-process replay cache. Suitable for single-
// instance dev; multi-replica deployments should back this with Postgres
// or Redis.
type MemoryReplay struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryReplay constructs an in-process ReplayCache.
func NewMemoryReplay() *MemoryReplay {
	return &MemoryReplay{entries: map[string]time.Time{}}
}

// Seen implements ReplayCache.
func (m *MemoryReplay) Seen(jti string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// Opportunistic GC: drop expired entries when we grow past 256.
	if len(m.entries) > 256 {
		for k, exp := range m.entries {
			if exp.Before(now) {
				delete(m.entries, k)
			}
		}
	}
	if exp, ok := m.entries[jti]; ok && exp.After(now) {
		return true, nil
	}
	m.entries[jti] = now.Add(ttl)
	return false, nil
}
