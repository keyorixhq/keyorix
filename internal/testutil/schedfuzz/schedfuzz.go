// Package schedfuzz is a seeded, deterministic concurrency scheduler used by
// the third-party connection-pool linearizability fuzzers under
// fuzz/thirdparty/pools (task SC1). It turns a fuzzer-chosen []byte program
// into a set of bounded goroutines, each carrying a list of operations and a
// per-operation "yield"/"sleep" schedule, so the interleaving of concurrent
// pool operations is driven by the fuzz corpus (reproducibly, from the same
// input bytes) rather than left entirely to the Go runtime scheduler.
//
// It deliberately mirrors the shape the repo's existing in-tree linearizability
// fuzzer already uses (server/http/concurrent_linearizable_fuzz_test.go's
// decodeCLProgram + per-goroutine clOp lists with a yield bit) so the two read
// the same way; the difference is that this helper targets the THIRD-PARTY
// pool/client (pgxpool, database/sql+modernc sqlite, gorm Tx) directly instead
// of the KeyorixCore layer, and adds the yield/sleep scheduling + the
// deadlock/goroutine-leak watchdog as shared, reusable machinery.
//
// Determinism note: the per-operation yield and sleep decisions are encoded in
// the program bytes, so a crashing input replays identically. The underlying
// Go scheduler is still nondeterministic between yields — that is the point of
// running under -race — but the corpus controls WHERE the yields land, which is
// what makes a reduced crasher reproducible enough to triage.
//
// Test-only: nothing outside *_test.go files may import this package.
package schedfuzz

import (
	"runtime"
	"testing"
	"time"
)

// Op is one scheduled operation for one goroutine. Kind/Key/Val are opaque
// selectors the target interprets (e.g. Kind%3 => read/write/cas, Key%N =>
// which register). Yield asks the runner to call runtime.Gosched() just before
// the op; Sleep asks for a tiny, bounded micro-sleep. Both widen the
// interleaving window at operation boundaries.
type Op struct {
	Kind  byte
	Key   byte
	Val   byte
	Yield bool
	Sleep bool
}

// Program is a decoded fuzz input: a bounded set of goroutines, each with its
// own op list, plus a GOMAXPROCS the iteration should run under.
type Program struct {
	Goroutines [][]Op
	GOMAXPROCS int
}

// Decode turns raw fuzz bytes into a Program. Bounds (maxGoroutines,
// maxOpsPerG, maxKeys) are the caller's; they keep a single iteration cheap
// enough to run millions of times and keep the recorded history small enough
// for porcupine to check in well under its timeout.
//
// Layout: byte0 selects goroutine count in [2, maxGoroutines]; byte1 selects
// GOMAXPROCS from {2, 4, NumCPU}; the remaining bytes are consumed 4 at a time
// as (kind, key, yield/sleep flags, val) and round-robined across goroutines.
func Decode(program []byte, maxGoroutines, maxOpsPerG, maxKeys int) Program {
	if maxGoroutines < 2 {
		maxGoroutines = 2
	}
	if len(program) < 2 {
		return Program{GOMAXPROCS: 2}
	}
	g := 2 + int(program[0])%(maxGoroutines-1)
	// ceiling is the GOMAXPROCS already in effect for this process
	// (runtime.GOMAXPROCS(0) reflects the GOMAXPROCS env var), so a shared-host
	// run that exports GOMAXPROCS=2 can never have a single fuzz iteration spike
	// the process above its core budget regardless of which value the corpus
	// picks — the same role the in-tree harness's KEYORIX_CL_GOMAXPROCS override
	// plays. A local/CI run with no cap keeps the full {2,4,NumCPU} variety.
	ceiling := max(runtime.GOMAXPROCS(0), 2)
	var gomaxprocs int
	switch program[1] % 3 {
	case 0:
		gomaxprocs = 2
	case 1:
		gomaxprocs = 4
	default:
		gomaxprocs = runtime.NumCPU()
	}
	if gomaxprocs > ceiling {
		gomaxprocs = ceiling
	}
	goroutines := make([][]Op, g)
	body := program[2:]
	total := 0
	maxTotal := maxGoroutines * maxOpsPerG
	for i := 0; i+3 < len(body) && total < maxTotal; i += 4 {
		gi := total % g
		if len(goroutines[gi]) >= maxOpsPerG {
			total++
			continue
		}
		flags := body[i+2]
		goroutines[gi] = append(goroutines[gi], Op{
			Kind:  body[i],
			Key:   body[i+1] % byte(maxKeys),
			Val:   body[i+3],
			Yield: flags&1 == 1,
			Sleep: flags&2 == 2,
		})
		total++
	}
	return Program{Goroutines: goroutines, GOMAXPROCS: gomaxprocs}
}

// Pace applies op's scheduling hints: an optional yield and an optional tiny
// bounded sleep. Call it immediately before performing the real pool
// operation. The sleep is capped at a few microseconds so a long program stays
// cheap; its only purpose is to occasionally let another goroutine win a race
// for a pooled connection.
func Pace(op Op) {
	if op.Yield {
		runtime.Gosched()
	}
	if op.Sleep {
		// Derived from Val so it is deterministic per input, capped tiny.
		d := time.Duration(1+int(op.Val)%8) * time.Microsecond
		time.Sleep(d)
	}
}

// RunBounded spawns n goroutines, runs fn(gi) in each, and waits up to timeout
// for all of them to finish. It returns true if they all completed, false if
// the timeout elapsed first (the DEADLOCK oracle: a pool operation that blocks
// forever — e.g. a connection never returned to a saturated pool, or a lock
// never released — manifests as goroutines that never finish). A false return
// is the caller's to fail on; RunBounded itself does not call t.Fatal so the
// caller can attach context.
//
// What it does NOT do: it does not kill the stuck goroutines (Go has no safe
// goroutine kill); on a false return the leaked goroutines remain, which the
// goroutine-leak oracle will then also observe. That is intentional — a real
// deadlock should trip BOTH oracles, and the test process exits at the end of
// the fuzz worker anyway.
func RunBounded(t testing.TB, n int, timeout time.Duration, fn func(gi int)) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		var wg = make(chan struct{}, n)
		for i := range n {
			go func(gi int) {
				defer func() { wg <- struct{}{} }()
				fn(gi)
			}(i)
		}
		for range n {
			<-wg
		}
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// GoroutineBaseline returns a settled goroutine count: it lets transient
// goroutines (a just-closed connection's reader, a finished timer) drain by
// polling until the count is stable across a short window or the attempts run
// out. Pair it with AssertNoGoroutineLeak after the concurrent phase.
func GoroutineBaseline() int {
	prev := runtime.NumGoroutine()
	for range 50 {
		time.Sleep(2 * time.Millisecond)
		runtime.GC()
		n := runtime.NumGoroutine()
		if n == prev {
			return n
		}
		prev = n
	}
	return prev
}

// SettleGoroutines waits for the live goroutine count to fall back to at most
// baseline+slack, returning the final count and whether it settled. The slack
// absorbs pool-internal goroutines (a health-checker, a connection reaper) that
// legitimately outlive a single operation but are bounded. A count that stays
// above baseline+slack after the settle window is a goroutine LEAK.
func SettleGoroutines(baseline, slack int) (int, bool) {
	for range 100 {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= baseline+slack {
			return n, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	runtime.GC()
	return runtime.NumGoroutine(), false
}
