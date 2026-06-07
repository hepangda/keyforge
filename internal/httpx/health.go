package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Probe checks one subsystem's readiness. It must return nil when the
// subsystem can serve traffic, or an error explaining why it cannot.
type Probe interface {
	Name() string
	Check(ctx context.Context) error
}

// ProbeFunc adapts a function to the Probe interface.
type ProbeFunc struct {
	N string
	F func(ctx context.Context) error
}

// Name returns the probe name.
func (p ProbeFunc) Name() string { return p.N }

// Check runs the wrapped function.
func (p ProbeFunc) Check(ctx context.Context) error { return p.F(ctx) }

// HealthHandler exposes /healthz and /readyz endpoints backed by Probes.
type HealthHandler struct {
	mu    sync.RWMutex
	live  []Probe
	ready []Probe
}

// NewHealthHandler returns an empty HealthHandler.
func NewHealthHandler() *HealthHandler { return &HealthHandler{} }

// AddLiveness registers a probe used by /healthz.
func (h *HealthHandler) AddLiveness(p Probe) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.live = append(h.live, p)
}

// AddReadiness registers a probe used by /readyz.
func (h *HealthHandler) AddReadiness(p Probe) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = append(h.ready, p)
}

// Live serves /healthz.
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	probes := h.live
	h.mu.RUnlock()
	h.serve(w, r, probes)
}

// Ready serves /readyz.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	probes := h.ready
	h.mu.RUnlock()
	h.serve(w, r, probes)
}

type probeResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type healthResponse struct {
	Status string        `json:"status"`
	Probes []probeResult `json:"probes,omitempty"`
}

func (h *HealthHandler) serve(w http.ResponseWriter, r *http.Request, probes []Probe) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	resp := healthResponse{Status: "ok"}
	for _, p := range probes {
		pr := probeResult{Name: p.Name(), Status: "ok"}
		if err := p.Check(ctx); err != nil {
			pr.Status = "fail"
			pr.Error = err.Error()
			resp.Status = "fail"
		}
		resp.Probes = append(resp.Probes, pr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if resp.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
