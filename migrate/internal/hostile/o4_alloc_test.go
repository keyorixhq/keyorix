package hostile

import (
	"io"
	"net/http"
	"testing"
)

// TestAllocLimitScalesWithRequests pins O4's budget: flat without
// AllocPerRequest, and linear in the backend request count with it (#184).
func TestAllocLimitScalesWithRequests(t *testing.T) {
	const per = 1 << 20
	h := New(Config{Routes: toyRoutes(), AllocPerRequest: per})
	defer h.Close()
	base := h.allocLimit()
	if base != 256<<20 {
		t.Fatalf("flat limit = %d, want %d", base, 256<<20)
	}
	for range 3 {
		resp, err := http.Get(h.URL() + "/secret")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	want := base + 16*uint64(h.wrote.Load()) + uint64(h.Requests())*per // #nosec G115 -- test counts
	if got := h.allocLimit(); got != want || h.Requests() < 3 {
		t.Fatalf("limit = %d after %d requests, want %d", got, h.Requests(), want)
	}
}
