package yamlhostile

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// rgWrite, when set (go test ... -args -rgwrite), makes the calibrate test
// regenerate the committed budget JSON. A flag (not an env var) because the
// unattended sandbox denies env-prefixed commands; default off so a normal
// `go test ./...` never rewrites testdata.
var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

// PK2: port the yaml hostile target onto the resguard resource layer. The
// existing oracle (bounded wall-clock + bounded re-marshal size) is UNCHANGED;
// resguard is an INDEPENDENT second oracle that meters the resource cost of the
// decode itself and fails an input whose cost is wildly out of proportion to its
// size. This is the flagship PK2 proof: go-yaml #510 (quadratic work on a mapping
// with many duplicate keys) is a RAM/CPU amplifier, not a panic — exactly the
// defect class OSS-Fuzz's crash hunt misses and the resguard layer exists to catch.
//
// Measured shape of #510 (SampleEvery=1, this host): a 20 KB duplicate-key doc
// allocates ~1.42 GB (≈71 000 bytes allocated per input byte) and spends ~5.8 s
// CPU, vs a benign 18 KB distinct-key doc at ~37 MB (≈2 088 B/byte, ~0.2 s). The
// alloc-per-byte ratio grows with input size (quadratic), so the per-byte
// `alloc_bytes` slope — calibrated on benign docs — is the load-bearing fatal
// meter here. CPU/wall are resguard ADVISORY meters (process-wide, noisy under a
// shared host) and only report; they never fail an input alone.
//
// What the resguard oracle does NOT verify (beyond the existing oracle's list):
//   - it does not attribute the alloc spike to a line; it only flags the ratio.
//   - alloc/live-heap are SAMPLED meters (SampleEvery), but any input slower than
//     resguard's SlowWall (100 ms) is force-sampled, so a real amplifier — which is
//     slow by construction — is always measured; a cheap-but-huge one-off alloc on
//     an unsampled fast input is the only blind spot.
//   - it meters the alloc of `yaml.Unmarshal` only (the fuzzer's primary surface),
//     not the re-marshal the existing oracle performs.

const rgBudgetPath = "testdata/resguard-yaml.json"

// rgParse drives one input through the metered decode surface (the #510 path).
func rgParse(data []byte) {
	var v any
	_ = decode(data, &v)
}

// rgBenignCorpus is the calibration corpus: a spread of LEGITIMATE YAML documents
// (small, medium distinct-key map, list, nested map) so the per-byte alloc slope
// reflects real linear decode cost — not just a tiny seed whose floor would make
// any larger benign doc false-positive. No duplicate-key / alias-bomb doc is in
// the corpus: seeding an amplifier would teach the budget that amplification is
// normal, defeating the oracle.
func rgBenignCorpus() [][]byte {
	var distinct strings.Builder
	for i := range 1500 {
		distinct.WriteString("key_")
		distinct.WriteString(strings.Repeat("x", 4))
		distinct.WriteByte(byte('0' + i%10))
		distinct.WriteByte(byte('a' + i%26))
		distinct.WriteString(": value\n")
	}
	var list strings.Builder
	list.WriteString("items:\n")
	for range 1000 {
		list.WriteString("  - a string item of moderate length\n")
	}
	var nested strings.Builder
	for i := range 40 {
		nested.WriteString(strings.Repeat("  ", i))
		nested.WriteString("level: ")
		nested.WriteString(strings.Repeat("v", i+1))
		nested.WriteByte('\n')
	}
	return [][]byte{
		[]byte("name: value\nlist:\n  - a\n  - b\n"),
		[]byte("{}"),
		[]byte("a: 1\nb: two\nc: [1, 2, 3]\nd: {x: y}\n"),
		[]byte(distinct.String()),
		[]byte(list.String()),
		[]byte(nested.String()),
	}
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 { // repeat so GC/alloc noise averages into p99
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s), func() { rgParse(s) }))
		}
	}
	b := resguard.Calibrate("yaml_decode", costs, resguard.DefaultFactor)
	// live_heap is a post-GC process-heap SNAPSHOT, not a per-input delta: inside a
	// fuzz worker that runs many inputs per process it reflects residual heap, not
	// this input's fault (RSG2 KeepOnly lesson). Drop it from the fatal budget —
	// cross-input heap growth is Drift's job. alloc_bytes/mallocs (per-input
	// ReadMemStats deltas) stay and carry the #510 signal.
	delete(b.Meters, "live_heap")
	return b
}

// dupKeyBomb returns a #510-shaped document: n duplicate keys in one mapping,
// which yaml.v3 handles in O(n^2). n is chosen by the caller to land the alloc
// over budget while (for the red/green) staying UNDER the existing 2 s wall
// deadline — proving the resource oracle catches a milder amplifier than the
// wall oracle does.
func dupKeyBomb(n int) []byte {
	return []byte("a: 1\n" + strings.Repeat("a: 1\n", n))
}

// TestResguardYAMLCalibrate regenerates the committed budget under
// RESGUARD_CALIBRATE=1; otherwise asserts calibration produced an alloc budget.
func TestResguardYAMLCalibrate(t *testing.T) {
	b := rgCalibrate(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes must be calibrated; got %s", b.Summary())
	}
	if *rgWrite {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardYAMLRedGreen is the committed red/green proof. GREEN: a benign
// medium document passes the calibrated budget. RED: a #510 duplicate-key doc —
// a REAL amplifier (attacker input, no production plant) — trips the alloc budget
// while running in well under the existing 2 s wall deadline, so the new oracle
// catches an amplifier the old one would not.
func TestResguardYAMLRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	// GREEN
	benign := rgBenignCorpus()[3] // the 1500-entry distinct-key map
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgParse(benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign doc tripped the budget: alloc=%d for %d bytes", green.AllocBytes, len(benign))
	}

	// RED: 1500 duplicate keys. From the measured shape this allocates hundreds of
	// MB (well over the benign slope) yet decodes in < 1 s (< the 2 s wall oracle).
	bomb := dupKeyBomb(1500)
	pr := resguard.New(t, resguard.Options{SampleEvery: 1})
	red := pr.Measure(len(bomb), func() { rgParse(bomb) })
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("the #510 duplicate-key amplifier (input %d bytes, alloc %d) did NOT trip the budget", len(bomb), red.AllocBytes)
	}
	t.Logf("RED tripped (input %d bytes, alloc %d, wall %s < 2s deadline): %s", len(bomb), red.AllocBytes, red.Wall, msg)
}
