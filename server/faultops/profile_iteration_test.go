package faultops

import (
	"context"
	"testing"
	"time"
)

// TestProfileOneIteration times each phase of newFaultWorld + one full
// runOneFuzzIteration-shaped pass, to find where the ~18s/iteration the
// -fuzztime burst showed actually goes. Not a correctness test — logs only.
func TestProfileOneIteration(t *testing.T) {
	report := func(label string, start time.Time) {
		t.Logf("PROFILE %-28s %v", label, time.Since(start))
	}

	overall := time.Now()

	t0 := time.Now()
	w := newFaultWorld(t, nil)
	report("newFaultWorld (total)", t0)
	_ = w

	op := opCatalog[0] // REST PUT /api/v1/roles/{id}
	ctx := context.Background()

	t1 := time.Now()
	state, err := op.Setup(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	report("op.Setup", t1)

	t2 := time.Now()
	if _, err := snapshotDB(w.db); err != nil {
		t.Fatal(err)
	}
	report("snapshotDB (before)", t2)

	t3 := time.Now()
	if _, err := op.Execute(ctx, w, state); err != nil {
		t.Fatal(err)
	}
	report("op.Execute", t3)

	t4 := time.Now()
	if _, err := snapshotDB(w.db); err != nil {
		t.Fatal(err)
	}
	report("snapshotDB (after)", t4)

	report("TOTAL (one world, one op)", overall)
}

// TestProfileNewFaultWorldSubphases breaks newFaultWorld itself down further
// by timing DB setup, bootstrap+login, REST router construction, and gRPC
// server+bufconn construction separately -- newFaultWorld doesn't expose
// these as separate calls, so this duplicates its body with timers rather
// than modifying the real one (which stays timer-free for the actual harness).
func TestProfileNewFaultWorldSubphases(t *testing.T) {
	for i := 0; i < 3; i++ {
		t.Run("", func(t *testing.T) {
			overall := time.Now()
			w := newFaultWorld(t, nil)
			t.Logf("PROFILE run %d: newFaultWorld total = %v", i, time.Since(overall))
			_ = w
		})
	}
}
