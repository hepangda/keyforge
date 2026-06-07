package observability

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestKeyforgeMetricPrefix enforces the keyforge_ prefix across every
// registered collector. Dashboards depend on this convention; a stray
// metric without the prefix would silently miss the rollup.
func TestKeyforgeMetricPrefix(t *testing.T) {
	m := New()
	ch := make(chan *prometheus.Desc, 64)
	go func() {
		m.Registry.Describe(ch)
		close(ch)
	}()
	saw := 0
	for d := range ch {
		saw++
		name := descName(d.String())
		if name == "" {
			continue
		}
		if !strings.HasPrefix(name, "keyforge_") {
			t.Errorf("metric %q does not have keyforge_ prefix", name)
		}
	}
	if saw == 0 {
		t.Fatal("no metric descriptors observed")
	}
}

// descName extracts the metric fqName from a *prometheus.Desc's String()
// representation, which has the form `Desc{fqName: "name", ...}`.
func descName(s string) string {
	const k = `fqName: "`
	i := strings.Index(s, k)
	if i < 0 {
		return ""
	}
	rest := s[i+len(k):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
