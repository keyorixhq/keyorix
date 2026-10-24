package faultops

import (
	"sync"
	"testing"
)

// maxLiveWorldDBsPerTest bounds how many world databases (openWorldDBTB) one test
// may hold open at once. A world's database lives until the test that opened it
// ends, and on Postgres each one keeps a pool of up to two connections and a
// schema. A test that drives many cases on one t therefore piles them up: the
// owed-audit calibration held 38 worlds on its RED subtest, 76 of the default 97
// usable connections on its own, and failed with SQLSTATE 53300 on a shared server
// (MERGE-FIX-3482H). Drive each case in its own subtest instead (as
// TestOwedAuditOracle_SweepEveryScopedOp does), so its worlds close when it ends.
//
// Counted per test (not per process), so t.Parallel tests do not add up, and on
// SQLite too, so default CI catches a new offender without a Postgres server.
// What it does not see: worlds held by a parent test while its subtests open
// their own (each t is counted on its own).
const maxLiveWorldDBsPerTest = 8

var liveWorldDBs = struct {
	sync.Mutex
	n map[tbLite]int
}{n: map[tbLite]int{}}

// trackWorldDB counts a world database opened on tb until tb's cleanup, and fails
// tb when it holds more than maxLiveWorldDBsPerTest at once.
func trackWorldDB(tb tbLite) {
	tb.Helper()
	liveWorldDBs.Lock()
	liveWorldDBs.n[tb]++
	n := liveWorldDBs.n[tb]
	liveWorldDBs.Unlock()
	tb.Cleanup(func() {
		liveWorldDBs.Lock()
		defer liveWorldDBs.Unlock()
		if liveWorldDBs.n[tb]--; liveWorldDBs.n[tb] <= 0 {
			delete(liveWorldDBs.n, tb)
		}
	})
	if n > maxLiveWorldDBsPerTest {
		tb.Fatalf("this test holds %d world databases open at once (limit %d): on Postgres each keeps a pool and a "+
			"schema until the test ends, and a test that piles them up runs the server out of connection slots "+
			"(SQLSTATE 53300). Drive each case in its own t.Run so its worlds close when it ends.", n, maxLiveWorldDBsPerTest)
	}
}

// TestTrackWorldDB_FailsATestThatPilesUpWorlds: the budget fails the test holding
// one world too many, frees a test's worlds when it ends, and keeps the counts of
// two tests apart.
func TestTrackWorldDB_FailsATestThatPilesUpWorlds(t *testing.T) {
	var over *testing.T
	t.Run("one world too many", func(t *testing.T) {
		over = t
		ft := &fatalRecorder{tbLite: t}
		for range maxLiveWorldDBsPerTest {
			trackWorldDB(ft)
		}
		if ft.fatal != "" {
			t.Fatalf("failed at the limit, not above it: %s", ft.fatal)
		}
		trackWorldDB(ft)
		if ft.fatal == "" {
			t.Fatalf("holding %d worlds at once was not reported", maxLiveWorldDBsPerTest+1)
		}
	})
	liveWorldDBs.Lock()
	left := len(liveWorldDBs.n)
	liveWorldDBs.Unlock()
	if left != 0 {
		t.Fatalf("%d test(s) still counted after their cleanups ran (subtest %s)", left, over.Name())
	}
	t.Run("two tests at the limit at once", func(t *testing.T) {
		a, b := &fatalRecorder{tbLite: t}, &fatalRecorder{tbLite: t}
		for range maxLiveWorldDBsPerTest {
			trackWorldDB(a)
			trackWorldDB(b)
		}
		if a.fatal != "" || b.fatal != "" {
			t.Fatalf("one test's worlds were counted against another: %q %q", a.fatal, b.fatal)
		}
	})
}

// fatalRecorder records Fatalf instead of ending the test, so the test above can
// observe the budget firing. It is its own map key, distinct from the t it wraps.
type fatalRecorder struct {
	tbLite
	fatal string
}

func (r *fatalRecorder) Helper() {}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	if r.fatal == "" {
		r.fatal = format
	}
}
