package demo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// DEMO-REHEARSAL-2: check.sh's latency step reads one secret 50 times in a burst. On a seeded
// secret (stripe-api-key) that raises frequency_spike / cumulative_rate alerts which stay open
// on the demo and which the "no open anomalies" step does not excuse (only new_user / new_ip
// and the scratch secret "check-secret" are). The probe must therefore read the scratch secret
// that verify-write created, while it still exists.

// verifyWriteAPI wraps the shared fake API with the verify-write endpoints and records every
// by-ref secret read made with the admin session.
type verifyWriteAPI struct {
	mu      sync.Mutex
	refs    []string
	rotated bool
}

func (v *verifyWriteAPI) adminReads() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.refs...)
}

func (v *verifyWriteAPI) handler(base http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", base)
	reply := func(w http.ResponseWriter, data any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}
	mux.HandleFunc("POST /api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"id": 7})
	})
	mux.HandleFunc("GET /api/v1/projects/7/environments", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"environments": []map[string]any{{"id": 9, "name": "development"}}})
	})
	mux.HandleFunc("DELETE /api/v1/projects/7", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]any{}) })
	mux.HandleFunc("POST /api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"id": 11})
	})
	mux.HandleFunc("GET /api/v1/secrets/11", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		val := map[bool]string{false: "v1-value", true: "v2-value"}[v.rotated]
		v.mu.Unlock()
		reply(w, map[string]any{"value": val})
	})
	mux.HandleFunc("POST /api/v1/secrets/11/rotate", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.rotated = true
		v.mu.Unlock()
		reply(w, map[string]any{})
	})
	mux.HandleFunc("GET /api/v1/secrets/11/versions", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"versions": []int{1, 2}})
	})
	mux.HandleFunc("DELETE /api/v1/secrets/11", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]any{}) })
	mux.HandleFunc("GET /api/v1/secrets/value", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok != "admin-session" { // the machine-identity read stays with the base fake
			base.ServeHTTP(w, r)
			return
		}
		v.mu.Lock()
		v.refs = append(v.refs, r.URL.Query().Get("ref"))
		v.mu.Unlock()
		reply(w, map[string]any{"value": "v"})
	})
	return mux
}

func TestCheck_LatencyProbeReadsTheScratchSecretNotASeededOne(t *testing.T) {
	e := newCheckEnv(t)
	vw := &verifyWriteAPI{}
	srv := httptest.NewServer(vw.handler(e.api.handler()))
	t.Cleanup(srv.Close)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), srv.URL)

	out, code := e.run(t, "admin login|verify-write|latency", "--url", srv.URL)
	if code != 0 {
		t.Fatalf("want exit 0, got %d:\n%s", code, out)
	}
	refs := vw.adminReads()
	if len(refs) != 50 {
		t.Fatalf("want the 50 latency reads, got %d: %v\n%s", len(refs), refs, out)
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, "demo-check-verify-") || !strings.HasSuffix(ref, "/development/check-secret") {
			t.Fatalf("latency probe read %q: it must read the scratch secret (project demo-check-verify-*, secret check-secret), "+
				"because a burst on a seeded secret leaves frequency_spike alerts open on the demo", ref)
		}
	}
}
