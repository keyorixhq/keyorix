package k8ssync

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status tracks the outcome of the most recent reconcile pass so the agent can serve
// Kubernetes liveness/readiness probes. It is safe for concurrent use: the reconcile
// loop records results while the HTTP handler reads them.
type Status struct {
	mu      sync.Mutex
	ran     bool
	lastRun time.Time
	last    Result
	now     func() time.Time
}

// NewStatus returns a Status with a real clock.
func NewStatus() *Status {
	return &Status{now: time.Now}
}

// Record stores the result of a completed reconcile pass.
func (s *Status) Record(res Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran = true
	s.lastRun = s.now()
	s.last = res
}

func (s *Status) snapshot() (bool, time.Time, Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ran, s.lastRun, s.last
}

// Handler serves the agent's probe + status endpoints:
//   - GET /healthz — liveness: always 200 while the process is responsive.
//   - GET /readyz  — readiness: 200 once at least one reconcile pass has completed,
//     503 before that (so traffic/rollout waits for the first sync).
//   - GET /status  — JSON of the last pass (counts + timestamp), for observability.
//
// No secret values are exposed — only counts, a timestamp, and an error count.
func (s *Status) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		ran, _, _ := s.snapshot()
		if !ran {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("no reconcile completed yet"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		ran, lastRun, last := s.snapshot()
		body := map[string]interface{}{
			"ran":       ran,
			"created":   last.Created,
			"updated":   last.Updated,
			"unchanged": last.Unchanged,
			"failed":    last.Failed,
			"errors":    len(last.Errors),
		}
		if ran {
			body["last_run"] = lastRun.UTC().Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	return mux
}
