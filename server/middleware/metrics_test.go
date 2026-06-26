package middleware

import (
	"net/http"
	"testing"
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
