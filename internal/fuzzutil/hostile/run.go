package hostile

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// logCapture swaps slog's default logger for a buffer for the life of a
// Harness, so the O7 leakage oracle can scan what connectors log.
type logCapture struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	prev *slog.Logger
}

func captureLogs() *logCapture {
	lc := &logCapture{prev: slog.Default()}
	slog.SetDefault(slog.New(slog.NewTextHandler(lc, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return lc
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buf.Len() < 1<<20 {
		l.buf.Write(p)
	}
	return len(p), nil
}

func (l *logCapture) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logCapture) restore() { slog.SetDefault(l.prev) }

// Logs returns what was captured from slog so far.
func (h *Harness) Logs() string { return h.logs.text() }

// census counts live goroutines by (top function, creator).
func census() map[string]int {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		lines := strings.Split(g, "\n")
		if len(lines) < 2 {
			continue
		}
		key := lines[1]
		if i := strings.Index(key, "("); i > 0 {
			key = key[:i]
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "created by ") {
				key += " <- " + l
				break
			}
		}
		if ignoredGoroutine(key) {
			continue
		}
		out[key]++
	}
	return out
}

// ignoredGoroutine skips process-level helpers that the Go runtime or the
// fuzz/test driver start lazily, once, and never stop (signal delivery, the
// pprof and testing machinery). They are not per-call leaks.
func ignoredGoroutine(key string) bool {
	for _, p := range []string{"os/signal.", "runtime/pprof.", "testing.", "runtime.ensureSigM", "internal/fuzz.", "runtime/trace.", "github.com/redis/go-redis/"} {
		if strings.Contains(key, p) {
			return true
		}
	}
	return false
}

func leaked(before, after map[string]int) []string {
	var out []string
	for k, n := range after {
		if n > before[k] {
			out = append(out, fmt.Sprintf("%s (+%d)", k, n-before[k]))
		}
	}
	sort.Strings(out)
	return out
}

func fdCount() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(es)
}

// Violate records an oracle violation; Finish reports them.
func (h *Harness) Violate(format string, args ...any) {
	h.mu.Lock()
	h.viol = append(h.viol, fmt.Sprintf(format, args...))
	h.mu.Unlock()
}

// Violations returns the violations recorded so far.
func (h *Harness) Violations() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.viol...)
}

// hangSlack is how long past its context deadline a call may take before O2
// reports a hang. 1 s produced false positives on PRISTINE programs when the
// rig host was saturated (two seen in the first campaign hour), so it is 4 s.
const hangSlack = 4 * time.Second

// leakWindow is how long Finish polls for goroutines/FDs to return to their
// pre-call census. 1.2 s gave one non-reproducible report (replayed 3/3 clean)
// on a saturated host, so it is 4 s.
const leakWindow = 4 * time.Second

// Run executes the connector call under the deadline, hang, panic and
// allocation oracles (O1, O2, O4) and scans the returned error and captured
// logs for leakage (O7). It returns the call's error.
func (h *Harness) Run(label string, fn func(ctx context.Context) error) error {
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	// A pristine program has no fault to wait for, so a deadline hit there is
	// host starvation (seen on the saturated rig host), never a finding. Give it
	// a long deadline so O6 (liveness) measures the connector, not the scheduler.
	timeout := h.cfg.CallTimeout
	if h.cfg.Program.Pristine() {
		timeout *= 10
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		err   error
		pv    any
		stack []byte
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			if x := recover(); x != nil {
				r.pv, r.stack = x, debug.Stack()
			}
			ch <- r
		}()
		r.err = fn(ctx)
	}()

	var r result
	select {
	case r = <-ch:
	case <-time.After(timeout + hangSlack):
		cancel()
		h.Violate("O2 HANG: %s did not return within %s of a %s context deadline", label, hangSlack, h.cfg.CallTimeout)
		return nil
	}
	cancel()

	if r.pv != nil {
		if h.cfg.RecoverPanics {
			h.Violate("O1 PANIC: %s: %v", label, r.pv)
			return nil
		}
		h.Close()
		panic(fmt.Sprintf("O1 PANIC in %s: %v\nprogram: %s\n%s", label, r.pv, h.cfg.Program, r.stack))
	}

	runtime.ReadMemStats(&m1)
	limit := uint64(256<<20) + 16*uint64(h.wrote.Load())
	if d := m1.TotalAlloc - m0.TotalAlloc; d > limit {
		h.Violate("O4 BOUNDED-WORK: %s allocated %d bytes (limit %d, server wrote %d)", label, d, limit, h.wrote.Load())
	}

	if r.err != nil {
		h.CheckLeak(label, r.err.Error())
	}
	return r.err
}

// CheckLeak applies O7 to a piece of text (an error string) and to the
// captured logs: neither may contain the canary or a credential the connector
// sent.
func (h *Harness) CheckLeak(label, text string) {
	secrets := append([]string{Canary}, h.cfg.Credentials...)
	logs := h.Logs()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(text, s) {
			h.Violate("O7 LEAK: %s: error text contains %q", label, s)
		}
		if strings.Contains(logs, s) {
			h.Violate("O7 LEAK: %s: log output contains %q", label, s)
		}
	}
}

// Finish closes the servers, applies the leak (O3), retry (O8) and redirect
// (O9) oracles and reports every recorded violation via fatalf.
func (h *Harness) Finish(fatalf func(format string, args ...any)) {
	h.Close()
	deadline := time.Now().Add(leakWindow)
	var lk []string
	for {
		lk = leaked(h.before, census())
		fdOK := h.fd0 < 0 || fdCount() <= h.fd0+2
		if len(lk) == 0 && fdOK {
			break
		}
		if time.Now().After(deadline) {
			if len(lk) > 0 {
				h.Violate("O3 LEAK: goroutines still alive %s after the call: %s", leakWindow, strings.Join(lk, "; "))
			}
			if !fdOK {
				h.Violate("O3 LEAK: open FDs %d, was %d before the call", fdCount(), h.fd0)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.Requests(); n > h.cfg.RequestCeiling {
		h.Violate("O8 UNBOUNDED-RETRIES: %d backend requests for one call (ceiling %d)", n, h.cfg.RequestCeiling)
	}
	if n := h.AttackerHits(); n > 0 {
		h.mu.Lock()
		hosts := append([]string(nil), h.attHosts...)
		h.mu.Unlock()
		tag := "O9/redirect-followed"
		if h.cfg.AllowRedirect {
			tag = "O9/port-hop"
			for _, host := range hosts {
				if strings.HasPrefix(host, "localhost") {
					tag = "O9/cross-host"
				}
			}
		}
		h.Violate("%s: the sentinel internal address received %d request(s) (Host: %v)", tag, n, hosts)
	}
	if !h.cfg.AllowRedirect {
		h.mu.Lock()
		for _, s := range h.served {
			if s.Followed {
				h.viol = append(h.viol, fmt.Sprintf("O9/redirect-followed: connector followed a same-origin redirect on route %q but is declared never to follow redirects", s.Route))
				break
			}
		}
		h.mu.Unlock()
	}
	if v := h.unallowed(); len(v) > 0 {
		fatalf("%s\nprogram: %s\nserved: %s", strings.Join(v, "\n"), h.cfg.Program, h.summary())
	}
}

// unallowed filters out violations whose tag prefix is listed in the
// KX_HOSTILE_ALLOW environment variable (comma separated, e.g. "O5/empty,O8").
// A campaign sets it ONLY for classes already triaged and logged as findings, so
// the native fuzzer (which stops at the first failure) can keep exploring; every
// suppressed hit is still printed to stderr as HOSTILE-KNOWN.
func (h *Harness) unallowed() []string {
	allow := strings.Split(os.Getenv("KX_HOSTILE_ALLOW"), ",")
	var out []string
	for _, v := range h.Violations() {
		known := false
		for _, a := range allow {
			if a = strings.TrimSpace(a); a != "" && strings.HasPrefix(v, a) {
				known = true
			}
		}
		if known {
			fmt.Fprintf(os.Stderr, "HOSTILE-KNOWN: %s | program: %s\n", v, h.cfg.Program)
			continue
		}
		out = append(out, v)
	}
	return out
}

func (h *Harness) summary() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var s []string
	for _, r := range h.served {
		s = append(s, fmt.Sprintf("%s#%d{active=%v status=%d complete=%v redirect=%d followed=%v bytes=%d}", r.Route, r.N, r.Active, r.Status, r.Complete, r.Redirect, r.Followed, len(r.Seen)))
	}
	if len(h.unmatch) > 0 {
		s = append(s, "unmatched="+strings.Join(h.unmatch, ","))
	}
	return strings.Join(s, " ")
}

// Unmatched lists requests the connector made to endpoints with no Route.
func (h *Harness) Unmatched() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.unmatch...)
}
