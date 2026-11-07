package wycheproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
)

// Result classes in the vector files.
const (
	resValid      = "valid"
	resInvalid    = "invalid"
	resAcceptable = "acceptable"
)

// Report collects failures and counters for one suite run, so a planted-defect
// test can assert that a suite fails without failing the Go test itself.
type Report struct {
	Name string
	Pins bool // enforce acceptable_pins.json for this run (only the real wrappers)
	// Known maps a vector id to a library behaviour that is tolerated for that
	// exact vector (the reason is kept in the maintainers' private notes). The
	// vector must still reproduce; if it stops, the entry has to be removed.
	Known map[string]bool
	fails []string
	n     int
	Stats map[string]int
}

func newReport(name string, pins bool) *Report {
	return &Report{Name: name, Pins: pins, Stats: map[string]int{}}
}

// Failf records one failure.
func (r *Report) Failf(format string, a ...any) {
	r.n++
	if len(r.fails) < 40 {
		r.fails = append(r.fails, fmt.Sprintf(format, a...))
	}
}

// Count adds to a named counter.
func (r *Report) Count(key string, d int) { r.Stats[key] += d }

// Failures is the number of failures recorded.
func (r *Report) Failures() int { return r.n }

// Err reports the failures to t.
func (r *Report) Err(t *testing.T) {
	t.Helper()
	for _, f := range r.fails {
		t.Error(f)
	}
	if r.n > len(r.fails) {
		t.Errorf("%s: ... and %d more failures", r.Name, r.n-len(r.fails))
	}
	allStats.add(r)
}

// Summary is "key=n key=n" sorted.
func (r *Report) Summary() string {
	keys := make([]string, 0, len(r.Stats))
	for k := range r.Stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s=%d ", k, r.Stats[k])
	}
	return strings.TrimSpace(sb.String())
}

type statsTable struct {
	mu   sync.Mutex
	rows map[string]string
}

var allStats = &statsTable{rows: map[string]string{}}

func (s *statsTable) add(r *Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[r.Name] = r.Summary()
}

// try runs f, converting a panic into a reported value.
func try(f func() bool) (accepted bool, panicked any) {
	defer func() {
		if p := recover(); p != nil {
			panicked = p
			accepted = false
		}
	}()
	return f(), nil
}

// Judge applies the pre-registered result semantics (RULES.md section 1).
// run evaluates the vector once. inScope=false means a valid vector outside
// the wrapper's declared scope: it must be rejected. The returned bool is the
// first evaluation's verdict.
func (r *Report) Judge(id, result string, flags []string, inScope bool, run func() bool) bool {
	acc, pan := try(run)
	if pan != nil {
		r.Failf("%s %s: PANIC %v (flags %v, result %s)", r.Name, id, pan, flags, result)
		return false
	}
	r.Count("vectors", 1)
	r.Count("vectors_"+result, 1)
	switch result {
	case resValid:
		if !inScope {
			r.Count("out_of_scope", 1)
			if acc {
				r.Failf("%s %s: out-of-scope valid vector accepted (flags %v)", r.Name, id, flags)
			}
			return acc
		}
		if !acc {
			r.Failf("%s %s: valid vector rejected (flags %v)", r.Name, id, flags)
		}
	case resInvalid:
		switch {
		case r.Known[id] && acc:
			r.Count("known_tolerated", 1)
		case r.Known[id]:
			r.Failf("%s %s: known-tolerated vector no longer reproduces; remove it from the table", r.Name, id)
		case acc:
			r.Failf("%s %s: INVALID vector accepted (flags %v)", r.Name, id, flags)
		}
	case resAcceptable:
		acc2, pan2 := try(run)
		if pan2 != nil || acc2 != acc {
			r.Failf("%s %s: acceptable vector evaluates inconsistently (flags %v)", r.Name, id, flags)
		}
		r.Count("acceptable_accepted", b2i(acc))
		r.Count("acceptable_rejected", b2i(!acc))
		if r.Pins {
			pinCheck(r, id, acc)
		}
	default:
		r.Failf("%s %s: unknown result class %q", r.Name, id, result)
	}
	return acc
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Reject asserts that a mutated input is rejected.
func (r *Report) Reject(label string, accepted func() bool) {
	acc, pan := try(accepted)
	r.Count("mutations", 1)
	if pan != nil {
		r.Failf("%s: PANIC on mutation %s: %v", r.Name, label, pan)
		return
	}
	if acc {
		r.Failf("%s: mutation accepted: %s", r.Name, label)
	}
}

// RejectRef asserts that a mutated input is rejected. A mutation that the
// wrapper accepts is a failure unless the reference primitive (the standard
// library called directly) accepts it too: then the mutation happens to be a
// valid input (for example another vector of the same key) and is counted.
func (r *Report) RejectRef(label string, accepted, reference func() bool) {
	acc, pan := try(accepted)
	r.Count("mutations", 1)
	if pan != nil {
		r.Failf("%s: PANIC on mutation %s: %v", r.Name, label, pan)
		return
	}
	if !acc {
		return
	}
	if ref, _ := try(reference); ref {
		r.Count("mutation_valid_per_reference", 1)
		return
	}
	r.Failf("%s: mutation accepted: %s", r.Name, label)
}

// ---- acceptable-vector pins ----

var (
	pinMu   sync.Mutex
	pinsMap map[string]string
	pinsNew = map[string]string{}
)

func pinsPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "acceptable_pins.json")
}

func loadPins() map[string]string {
	if pinsMap != nil {
		return pinsMap
	}
	pinsMap = map[string]string{}
	if b, err := os.ReadFile(pinsPath()); err == nil { // #nosec G304 -- fixed repo path
		_ = json.Unmarshal(b, &pinsMap)
	}
	return pinsMap
}

func pinCheck(r *Report, id string, accepted bool) {
	pinMu.Lock()
	defer pinMu.Unlock()
	got := "reject"
	if accepted {
		got = "accept"
	}
	key := r.Name + "/" + id
	if os.Getenv("WYCHEPROOF_RECORD") == "1" {
		pinsNew[key] = got
		return
	}
	want, ok := loadPins()[key]
	if !ok {
		r.Failf("%s: acceptable vector has no pin (outcome %s); review and record with WYCHEPROOF_RECORD=1", key, got)
		return
	}
	if want != got {
		r.Failf("%s: acceptable vector outcome changed: pinned %s, now %s", key, want, got)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if os.Getenv("WYCHEPROOF_RECORD") == "1" && len(pinsNew) > 0 {
		merged := map[string]string{}
		for k, v := range loadPins() {
			merged[k] = v
		}
		for k, v := range pinsNew {
			merged[k] = v
		}
		b, _ := json.MarshalIndent(merged, "", " ")
		_ = os.WriteFile(pinsPath(), append(b, '\n'), 0o600)
	}
	if os.Getenv("WYCHEPROOF_STATS") == "1" {
		keys := make([]string, 0, len(allStats.rows))
		for k := range allStats.rows {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("STATS %-40s %s\n", k, allStats.rows[k])
		}
	}
	os.Exit(code)
}

// loadVectors loads a vector file or skips (fails with WYCHEPROOF_REQUIRE=1).
func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	err := wvec.Load(name, v)
	if err == nil {
		return
	}
	if errors.Is(err, wvec.ErrMissing) && os.Getenv("WYCHEPROOF_REQUIRE") != "1" {
		t.Skip(err.Error())
	}
	t.Fatal(err)
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

// flipBit returns a copy of b with bit i flipped.
func flipBit(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i/8] ^= 1 << (uint(i) % 8)
	return c
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func eq(a, b []byte) bool { return string(a) == string(b) }
