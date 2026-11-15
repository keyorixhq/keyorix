// world_leak_test.go — the IF1 memory-precondition harness.
//
// faultops fuzz workers were observed to grow ~2.5 MB resident per execution
// (FuzzMixedPrincipalAuthority reached 2.9 GB in 4 minutes at one worker). The
// SQLite DB is closed per iteration (openWorldDBTB's t.Cleanup), so the growth
// is something each world leaves ALIVE past its own t.Cleanup.
//
// Root cause (confirmed by the heap profile this file's KEYORIX_FAULTOPS_LEAKPROF
// run produces): every world's bootstrap+login and every authenticated request
// validates a session, which calls KeyorixCore.lastUsed().record(...). record
// arms a 30 s time.AfterFunc (last_used_coalescer.go:armTimerLocked). That timer
// holds the coalescer, which holds the whole *KeyorixCore graph (storage, gorm
// pool, permission/RBAC caches). The coalescer has no Stop; nothing in the world
// quiesces it. A world torn down in under 30 s leaves its timer armed, pinning
// its core for the timer's lifetime; and when the timer finally fires against the
// now-closed DB the flush fails, so finishFlush re-arms it — pinning the core
// FOREVER. N worlds => N pinned core graphs.
//
// The fix (world_test.go / world_reuse_test.go, TEST-ONLY): register a cleanup
// that calls core.FlushLastUsed before the DB-close cleanup runs (LIFO ordering),
// which stops the timer and empties pending so nothing re-arms. The underlying
// "a permanently-failing DB re-arms the last-used timer forever, holding the
// pending set and the core it belongs to" is a hardening observation; it is
// benign in production (one long-lived core) but the harness must not depend on
// that.
package faultops

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"
)

// residentBytes reads this process's resident set size from /proc/self/statm
// (field 2, resident pages) × page size. Linux-only; the CI hosts are
// Linux. Returns 0 if /proc is unavailable so the caller can fall back to
// runtime heap stats.
func residentBytes(tb tbLite) uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	var size, resident uint64
	if _, err := fmt.Sscanf(string(data), "%d %d", &size, &resident); err != nil {
		return 0
	}
	return resident * uint64(os.Getpagesize())
}

// buildAndExerciseWorld builds one world and drives exactly one authenticated
// operation through a real transport, so the session-validation path that arms
// the last-used timer runs — the same engagement a real fuzz iteration causes.
// It runs inside its own t.Run so the per-input t.Cleanup semantics a fuzz
// iteration has are reproduced exactly (servers/conn/DB torn down here).
func buildAndExerciseWorld(t *testing.T) {
	w := newFaultWorld(t, nil)
	ctx := context.Background()
	op := opCatalog[0] // REST PUT /api/v1/roles/{id} — authenticated REST round-trip
	state, err := op.Setup(ctx, w)
	if err != nil {
		t.Fatalf("op.Setup: %v", err)
	}
	if _, err := op.Execute(ctx, w, state); err != nil {
		t.Fatalf("op.Execute: %v", err)
	}
}

// heapAllocAfterGC returns HeapAlloc after two GC cycles so finalizers and
// deferred frees settle. Two cycles because a single GC can leave objects whose
// finalizer only queues the next-cycle free.
func heapAllocAfterGC() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestWorldFixtureLeakProfile is the profiling run (not a correctness gate):
// it builds worlds back to back for KEYORIX_FAULTOPS_LEAK_ITERS iterations
// (default 40), sampling RSS, HeapAlloc and goroutine count every 8 worlds, and
// writes a heap profile to KEYORIX_FAULTOPS_LEAKPROF if set. Used to produce a
// before/after RSS time series and the pprof that names the leak.
func TestWorldFixtureLeakProfile(t *testing.T) {
	if os.Getenv("KEYORIX_FAULTOPS_LEAK") == "" {
		t.Skip("profiling only; set KEYORIX_FAULTOPS_LEAK=1 to run")
	}
	iters := 40
	if v := os.Getenv("KEYORIX_FAULTOPS_LEAK_ITERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			iters = n
		}
	}
	start := time.Now()
	base := heapAllocAfterGC()
	t.Logf("LEAK iter=%-4d rss=%8dKiB heap=%8dKiB goroutines=%-5d t=%v",
		0, residentBytes(t)/1024, base/1024, runtime.NumGoroutine(), time.Since(start).Round(time.Millisecond))
	for i := 1; i <= iters; i++ {
		t.Run("", buildAndExerciseWorld)
		if i%8 == 0 || i == iters {
			h := heapAllocAfterGC()
			t.Logf("LEAK iter=%-4d rss=%8dKiB heap=%8dKiB goroutines=%-5d t=%v",
				i, residentBytes(t)/1024, h/1024, runtime.NumGoroutine(), time.Since(start).Round(time.Millisecond))
		}
	}
	if path := os.Getenv("KEYORIX_FAULTOPS_LEAKPROF"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create memprofile: %v", err)
		}
		defer func() { _ = f.Close() }()
		_ = heapAllocAfterGC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			t.Fatalf("write memprofile: %v", err)
		}
		t.Logf("LEAK wrote heap profile to %s", path)
	}
}

// TestWorldFixtureNoRetainedMemoryGrowth is the correctness gate for the
// memory fix: it builds a warmup world (to pay one-time init costs — i18n,
// package-level caches, first gorm pool), measures HeapAlloc, builds N more
// worlds, and asserts the per-world retained HeapAlloc is bounded. With the leak
// present each world pins a whole *KeyorixCore (hundreds of KiB to MiB); with the
// fix the delta per world is near zero. The bound is deliberately loose (256 KiB
// per world) so it fails loudly on a regression that re-pins the core graph but
// does not flake on ordinary allocator noise.
//
// Red proof: temporarily make newFaultWorld's quiesce-cleanup a no-op (or revert
// the FlushLastUsed cleanup) and this fails with per-world growth in the MiB.
func TestWorldFixtureNoRetainedMemoryGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("builds many worlds; skipped under -short")
	}
	const n = 24
	const maxPerWorldBytes = 256 * 1024

	t.Run("warmup", buildAndExerciseWorld)
	before := heapAllocAfterGC()
	beforeGoroutines := runtime.NumGoroutine()

	for range n {
		t.Run("", buildAndExerciseWorld)
	}
	after := heapAllocAfterGC()
	afterGoroutines := runtime.NumGoroutine()

	var grown int64
	if after > before {
		grown = int64(after - before)
	}
	perWorld := grown / n
	t.Logf("retained heap: before=%dKiB after=%dKiB grown=%dKiB over %d worlds = %dKiB/world; goroutines %d->%d",
		before/1024, after/1024, grown/1024, n, perWorld/1024, beforeGoroutines, afterGoroutines)

	if perWorld > maxPerWorldBytes {
		t.Fatalf("world fixture retains %d bytes/world (> %d bound): a torn-down world is still pinned "+
			"(most likely the last-used coalescer's armed timer holding its *KeyorixCore). "+
			"Confirm newFaultWorld quiesces the coalescer before the DB closes.", perWorld, maxPerWorldBytes)
	}
}
