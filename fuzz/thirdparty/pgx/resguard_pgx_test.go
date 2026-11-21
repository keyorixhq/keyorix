package pgxhostile

// resguard_pgx_test.go — PK1 port of the pgx hostile-server targets onto the
// shared resguard resource layer (internal/fuzzutil/resguard).
//
// WHY: the existing pgx oracles are no-panic + bounded-time only; memory is
// "approximated by Go's own alloc behaviour under -fuzz" (see the file headers),
// which is exactly the RAM-spike class PK1 exists to measure directly. Each input
// is now driven through a resguard.Probe that measures alloc / mallocs / live-heap
// (sampled) and process CPU (advisory), and checked against a per-target budget
// calibrated on a benign corpus. The pre-existing panic/hang oracles are UNCHANGED
// — they live in the drivePgx* functions this file calls; resguard is ADDED around
// them, never substituted for them.
//
// Network/sleep meters are NOT wired here: the pgx harness dials its own loopback
// fake server, so the air-gap/sleep oracles (which target the SDK connectors) do
// not apply (brief: "network/sleep meters apply to the connector ones").
//
// Budget model (brief): per-byte SLOPE for the response PARSERS (SimpleQuery /
// Extended / Copy — a small reply that drives super-linear alloc is the defect),
// AbsMax for the fixed-shape HANDSHAKE and SSL-negotiation targets (alloc is set
// by connection setup, not by the tiny input, so an input-size-independent ceiling
// is the right model).
//
// What this oracle does NOT verify: it does not prove correctness, only alloc
// proportion; alloc/live-heap are SAMPLED (1-in-32 inputs + any input slower than
// SlowWall), so a bomb confined to an unsampled fast input is seen late; CPU is a
// process-wide getrusage delta (advisory, never fatal, noisy under -parallel); the
// meter sees the whole drivePgx* call (server goroutine + driver) because alloc is
// a process-wide ReadMemStats delta, so it cannot attribute an alloc to the driver
// vs the test server.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/keyorixhq/keyorix/internal/pgxlimits"
)

const (
	pgxBudgetHandshake   = "testdata/resguard-pgx-handshake.json"
	pgxBudgetSimpleQuery = "testdata/resguard-pgx-simplequery.json"
	pgxBudgetExtended    = "testdata/resguard-pgx-extended.json"
	pgxBudgetCopy        = "testdata/resguard-pgx-copy.json"
	pgxBudgetSSL         = "testdata/resguard-pgx-ssl.json"
)

// pgxResguardProbe builds one Probe per testing.F and loads the target's committed
// budget. SampleEvery 32 keeps the expensive alloc sample off the hot path (the
// per-byte slope still catches a slow/large input via the SlowWall trigger).
func pgxResguardProbe(f *testing.F, budgetPath string) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(budgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", budgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

// pgxWarmOnce charges pgx/pgtype/regexp one-time initialisation (a default type
// map, compiled regexps, the first net.open) to an unmetered call. Without it the
// FIRST metered input in a cold process, which is every fuzz worker, pays ~160 KB
// the warm-calibrated budgets never saw: FuzzPgxSSLNegotiation failed on its
// 1-byte seed at 241 KB against a 77 KB budget. Calibration warms the same way, so
// the budget and the measurement agree on what "one input's cost" includes.
var pgxWarmOnce sync.Once

func pgxWarm(t *testing.T) {
	pgxWarmOnce.Do(func() {
		drivePgxSSL(t, pgxBenignSSL[0])
		drivePgxHandshake(t, pgxBenignHandshake[0])
	})
}

// measurePgx drives one input through the Probe, feeds the cost-guided engine, and
// applies the budget. The pre-existing panic/hang oracles run INSIDE drive.
func measurePgx(t *testing.T, probe *resguard.Probe, budget resguard.Budget, haveBudget bool, server []byte, drive func(*testing.T, []byte)) {
	pgxWarm(t)
	cost := probe.Measure(len(server), func() { drive(t, server) })
	resguard.FeedCoverage(cost)
	if haveBudget {
		budget.Check(t.Fatalf, cost)
	}
}

// ---- calibration -----------------------------------------------------------

// pgxMemMeters are the per-input-attributable meters PK1 keeps for the pgx
// parsers. alloc_bytes (TotalAlloc delta across the input) and mallocs are a
// single input's own allocation — the RAM-spike signal (the pkcs7 130 B→1.8 GB
// class is total allocation). cpu_ns is kept but is advisory (process-wide, never
// fatal). live_heap is deliberately NOT kept: it is absolute whole-process
// HeapAlloc-after-GC, so under -parallel + the fuzz engine's own in-memory corpus
// it reflects process state, not this input's cost, and would false-positive (a
// real retained-memory leak is Drift's job, not Budget's — same reasoning the RSG2
// Azure pilot used to drop it). The disk/net/db meters never fire here.
var pgxMemMeters = []string{"alloc_bytes", "mallocs", "cpu_ns"}

// a larger-but-benign handshake: AuthenticationOk, three ParameterStatus lines,
// BackendKeyData, ReadyForQuery — a legitimate server greeting, so the AbsMax
// ceiling for the handshake targets is not calibrated against the tiniest reply.
func benignBigHandshake() []byte {
	ps := func(k, v string) []byte {
		body := append([]byte(k), 0)
		body = append(body, []byte(v)...)
		body = append(body, 0)
		n := len(body) + 4
		return append([]byte{'S', byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, body...)
	}
	out := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0} // AuthenticationOk
	out = append(out, ps("server_version", "17.0 (Keyorix fuzz)")...)
	out = append(out, ps("client_encoding", "UTF8")...)
	out = append(out, ps("DateStyle", "ISO, MDY")...)
	out = append(out, 'K', 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 2) // BackendKeyData
	out = append(out, 'Z', 0, 0, 0, 5, 'I')                     // ReadyForQuery
	return out
}

var (
	pgxBenignHandshake = [][]byte{
		{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I'},
		{'R', 0, 0, 0, 8, 0, 0, 0, 3},
		{'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4},
		{'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0},
		benignBigHandshake(),
	}
	pgxBenignSimpleQuery = [][]byte{
		{'C', 0, 0, 0, 11, 'C', 'R', 'E', 'A', 'T', 'E', 0, 'Z', 0, 0, 0, 5, 'I'},
		{'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0},
		{'T', 0, 0, 0, 6, 0, 1, 'D', 0, 0, 0, 10, 0, 1, 0, 0, 0, 2, 'h', 'i'},
		buildNoticeFlood(64), // a legitimate (bounded) notice run
	}
	pgxBenignExtended = [][]byte{
		{'1', 0, 0, 0, 4, '2', 0, 0, 0, 4, 'C', 0, 0, 0, 5, 0, 'Z', 0, 0, 0, 5, 'I'},
		{'t', 0, 0, 0, 6, 0, 0, 'n', 0, 0, 0, 4},
	}
	pgxBenignCopy = [][]byte{
		{'H', 0, 0, 0, 7, 0, 0, 1, 0, 0, 'd', 0, 0, 0, 6, 'h', 'i', 'c', 0, 0, 0, 4, 'Z', 0, 0, 0, 5, 'I'},
		{'W', 0, 0, 0, 7, 0, 0, 1, 0, 0, 'Z', 0, 0, 0, 5, 'I'},
		{'G', 0, 0, 0, 7, 0, 0, 1, 0, 0, 'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0},
	}
	// 'S' (server accepts SSL) starts a client TLS handshake against whatever
	// follows, which allocates tls state a bare 'N'/'E' never does; a corpus
	// without it calibrated the absolute ceiling too small (the fuzzer found
	// "S\x16\x03\x00\x38." at 89 KB against 77 KB within seconds).
	pgxBenignSSL = [][]byte{
		{'N'},
		{'E', 'x'},
		{'S'},
		{'S', 0x16, 0x03, 0x03, 0x00, 0x00}, // 'S' then a TLS record header with an empty body
	}
)

// calibratePgx runs one target's benign corpus through a SampleEvery=1 probe (so
// every seed gets an alloc sample), calibrates, keeps only the memory/CPU meters,
// and optionally switches them to AbsMax. Returns the budget.
func calibratePgx(t testing.TB, name string, corpus [][]byte, drive func(*testing.T, []byte), absolute, lengthPrefixed bool) resguard.Budget {
	t.Helper()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	var costs []resguard.Cost
	tt := t.(*testing.T)
	pgxWarm(tt)
	for range 3 { // repeat to fold scheduling/GC noise into p99
		for _, seed := range corpus {
			costs = append(costs, probe.Measure(len(seed), func() { drive(tt, seed) }))
		}
	}
	b := resguard.Calibrate(name, costs, resguard.DefaultFactor)
	b.KeepOnly(pgxMemMeters...)
	if absolute {
		b.UseAbsolute(pgxMemMeters...)
	}
	if lengthPrefixed {
		// A server-claimed message length sizes one read buffer before the body
		// arrives, bounded by what production enforces (pgxlimits). The per-byte
		// slope is the wrong model for that; see
		// INV-RES-bounded-absolute-from-product-cap.
		b.UseBoundedAbsolute("alloc_bytes", pgxlimits.MaxProtocolMessageBodyLen)
	}
	return b
}

type pgxCalTarget struct {
	name     string
	path     string
	corpus   [][]byte
	drive    func(*testing.T, []byte)
	absolute bool
	// lengthPrefixed marks a target whose allocation is set by a server-claimed
	// message length (see INV-RES-bounded-absolute-from-product-cap).
	lengthPrefixed bool
}

func pgxCalTargets() []pgxCalTarget {
	return []pgxCalTarget{
		{"pgx_handshake", pgxBudgetHandshake, pgxBenignHandshake, drivePgxHandshake, true, true},
		{"pgx_simplequery", pgxBudgetSimpleQuery, pgxBenignSimpleQuery, drivePgxSimpleQuery, false, true},
		{"pgx_extended", pgxBudgetExtended, pgxBenignExtended, drivePgxExtended, false, true},
		{"pgx_copy", pgxBudgetCopy, pgxBenignCopy, drivePgxCopy, false, true},
		{"pgx_ssl", pgxBudgetSSL, pgxBenignSSL, drivePgxSSL, true, false},
	}
}

// TestResguardPgxCalibrate regenerates the committed pgx budgets when
// RESGUARD_CALIBRATE=1; otherwise it asserts each target produced a memory budget.
func TestResguardPgxCalibrate(t *testing.T) {
	for _, tgt := range pgxCalTargets() {
		b := calibratePgx(t, tgt.name, tgt.corpus, tgt.drive, tgt.absolute, tgt.lengthPrefixed)
		if len(b.Meters) == 0 {
			t.Fatalf("%s: no memory meter calibrated; %s", tgt.name, b.Summary())
		}
		if os.Getenv("RESGUARD_CALIBRATE") == "1" {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := b.WriteJSON(tgt.path); err != nil {
				t.Fatalf("%s: write budget: %v", tgt.name, err)
			}
			t.Logf("wrote %s: %s", tgt.path, b.Summary())
		}
	}
}

// TestResguardPgxRedGreen is the committed red/green proof for the pgx memory
// oracle. GREEN: a benign measured reply passes the calibrated budget. RED: the
// SAME benign reply's measured Cost with its allocation scaled to a bomb-sized
// value trips the budget, naming alloc_bytes. (pgx's hardened pgproto3 parser does
// not itself amplify on any seed — see the report — so RED is a synthesized
// over-budget Cost that proves the port's oracle fires end-to-end; the fuzz run
// additionally exercises real hostile inputs against the same budget.)
func TestResguardPgxRedGreen(t *testing.T) {
	b := calibratePgx(t, "pgx_simplequery", pgxBenignSimpleQuery, drivePgxSimpleQuery, false, true)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	seed := pgxBenignSimpleQuery[0]
	green := probe.Measure(len(seed), func() { drivePgxSimpleQuery(t, seed) })

	// GREEN: the benign reply must pass.
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign simple-query reply (alloc=%d) must pass the budget", green.AllocBytes)
	}

	// BOUNDARY: the ceiling is the calibrated value plus the product-enforced
	// bound, so it must sit exactly between "at the bound" (passes) and one byte
	// over it (fires), and a ~775 MB claimed-length allocation must fire.
	ceiling := b.Meters["alloc_bytes"].AbsMax
	at, over := green, green
	at.Sampled, over.Sampled = true, true
	at.AllocBytes, over.AllocBytes = uint64(ceiling), uint64(ceiling)+1
	if b.Check(func(string, ...any) {}, at) {
		t.Fatalf("BOUNDARY: alloc exactly at the ceiling (%d) must pass", at.AllocBytes)
	}
	if !b.Check(func(string, ...any) {}, over) {
		t.Fatalf("BOUNDARY: alloc one byte over the ceiling (%d) must fire", over.AllocBytes)
	}
	huge := at
	huge.AllocBytes = 775 << 20
	if !b.Check(func(string, ...any) {}, huge) {
		t.Fatalf("BOUNDARY: a ~775 MB claimed-length allocation must fire")
	}

	// RED: the same input, but a 1000x alloc amplification (the shape of a
	// length-prefix that drove pgx to allocate far past its input).
	red := green
	red.Sampled = true
	red.AllocBytes = green.AllocBytes*1000 + 1<<30
	red.Mallocs = green.Mallocs*1000 + 1
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("RED: a 1000x alloc amplification must trip the budget")
	}
	if !strings.Contains(msg, "alloc_bytes") {
		t.Fatalf("RED: failure message should name alloc_bytes: %q", msg)
	}
	t.Logf("GREEN alloc=%d passes; RED alloc=%d fires: %s", green.AllocBytes, red.AllocBytes, msg)
}
