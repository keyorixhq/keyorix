// fuzz_pg_fault_commit_test.go is FuzzPGFaultCommit: it drives keyorix's real
// audit-commit path against a real PostgreSQL server while a TCP fault proxy
// cuts or stalls the connection at an input-chosen point of the v3 wire
// protocol, and asserts the durability oracles (commit_oracle_test.go) hold for
// every input.
//
// Per-input resource bounds (FS-PG RULES — bounded time and allocations):
//   - time: every commit carries a short context deadline (perCommitFuzz), the
//     burst length is bounded (<= maxBurst), and the whole input is asserted to
//     finish within maxInputWall. A stall fault therefore cannot hang an input.
//   - allocations: the per-message read is capped at maxPGMessage (proxy_test.go)
//     so a corrupt length never drives an unbounded allocation, and the input's
//     own TotalAlloc delta is asserted under maxInputAlloc.
//   - connections: the proxied pool is capped at 1 connection; the throwaway
//     fspg_ database is reused across inputs (truncated), so the fuzzer does not
//     create a database per input.
package pgfault

import (
	"runtime"
	"testing"
	"time"
)

const (
	perCommitFuzz = 1500 * time.Millisecond
	stallForFuzz  = 2 * time.Second
	maxBurst      = 32
	maxInputWall  = 25 * time.Second
	maxInputAlloc = 256 << 20 // 256 MiB per input
)

// decodeFuzzFault maps raw bytes to a bounded fault spec + burst length.
func decodeFuzzFault(data []byte) (faultSpec, int) {
	b := func(i int) byte {
		if i < len(data) {
			return data[i]
		}
		return 0
	}
	modes := []faultMode{faultCut, faultStall, faultNone}
	mode := modes[int(b(0))%len(modes)]
	dir := dirBackend
	if b(1)&1 == 1 {
		dir = dirFrontend
	}
	n := 1 + int(b(2))%40    // 1..40 typed messages after arm
	burst := 4 + int(b(3))%maxBurst
	spec := faultSpec{mode: mode, dir: dir, n: n}
	if mode == faultStall {
		spec.stallFor = stallForFuzz
	}
	return spec, burst
}

func FuzzPGFaultCommit(f *testing.F) {
	// Seeds: a cut in the ack window, a cut before COMMIT is sent, a stall, and
	// a no-op (reference) — one per protocol point the oracle cares about.
	f.Add([]byte{0, 0, 1, 10})  // cut backend n=1
	f.Add([]byte{0, 1, 3, 12})  // cut frontend n=3
	f.Add([]byte{1, 0, 2, 8})   // stall backend n=2
	f.Add([]byte{2, 0, 5, 16})  // no fault (reference)
	f.Add([]byte{0, 0, 40, 24}) // cut far out (may not trip)

	w := newPGWorld(f) // once per worker process; truncated per input

	f.Fuzz(func(t *testing.T, data []byte) {
		spec, burst := decodeFuzzFault(data)

		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		start := time.Now()

		o := runFaultCaseT(t, w, spec, burst, perCommitFuzz)
		assertOracles(t, "fuzz", o)

		elapsed := time.Since(start)
		runtime.ReadMemStats(&m1)
		allocDelta := m1.TotalAlloc - m0.TotalAlloc

		if elapsed > maxInputWall {
			t.Errorf("resource bound: input took %v > %v (spec=%+v burst=%d)", elapsed, maxInputWall, spec, burst)
		}
		if allocDelta > maxInputAlloc {
			t.Errorf("resource bound: input allocated %d bytes > %d (spec=%+v burst=%d)", allocDelta, uint64(maxInputAlloc), spec, burst)
		}
	})
}
