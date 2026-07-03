package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// The method label must be bounded to a fixed allow-list so an attacker sending arbitrary
// RFC-7230 method tokens cannot spawn unbounded Prometheus time series (memory DoS).
func TestNormalizeMethod(t *testing.T) {
	for _, m := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodTrace,
	} {
		if got := normalizeMethod(m); got != m {
			t.Errorf("normalizeMethod(%q) = %q; want %q", m, got, m)
		}
	}
	for _, m := range []string{"AAAA", "BBBB", "lowercaseget", "FOOBAR", ""} {
		if got := normalizeMethod(m); got != "other" {
			t.Errorf("normalizeMethod(%q) = %q; want %q", m, got, "other")
		}
	}
}

// The /metrics exposition endpoint is unauthenticated by design (standard for
// Prometheus scraping), so go_info (exact Go version) and process_start_time_seconds
// (process uptime) must not appear in its output — minor recon information an
// unauthenticated caller could otherwise read. Other default Go-runtime/process
// metrics (go_goroutines is a stable, always-present one) must still be exposed, so
// the filter isn't accidentally dropping everything.
func TestMetricsHandler_SuppressesReconMetrics(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	for name := range suppressedMetricFamilies {
		if strings.Contains(body, "\n"+name+" ") || strings.Contains(body, "\n"+name+"{") ||
			strings.HasPrefix(body, name+" ") || strings.HasPrefix(body, name+"{") {
			t.Errorf("expected %q to be suppressed from /metrics output, but found it", name)
		}
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Error("expected an unsuppressed Go-runtime metric (go_goroutines) to still be present")
	}
}

// filteringGatherer itself, in isolation, drops exactly the named families and keeps
// everything else — pinned at the unit level independent of what the process
// registry happens to contain.
func TestFilteringGatherer_DropsOnlyNamedFamilies(t *testing.T) {
	name1, name2, name3 := "dropped_one", "dropped_two", "kept"
	fam := func(n string) *dto.MetricFamily { return &dto.MetricFamily{Name: &n} }
	inner := fakeGatherer{mfs: []*dto.MetricFamily{fam(name1), fam(name2), fam(name3)}}
	g := filteringGatherer{inner: inner, drop: map[string]bool{name1: true, name2: true}}

	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mfs) != 1 || mfs[0].GetName() != name3 {
		t.Fatalf("expected only %q to remain, got %v", name3, mfs)
	}
}

type fakeGatherer struct {
	mfs []*dto.MetricFamily
}

func (f fakeGatherer) Gather() ([]*dto.MetricFamily, error) {
	return f.mfs, nil
}
