package kdfmeter

import "testing"

// TestNotifyWithNoObserverAllocatesNothing is the machine check behind
// INV-KDFMETER-zero-cost-when-off's "no allocation" claim: with no observer
// installed, the per-call hook (one atomic load and a nil check) allocates nothing.
// bcrypt itself allocates, so the hook is measured on its own rather than through
// the wrapped call.
func TestNotifyWithNoObserverAllocatesNothing(t *testing.T) {
	prev := SetObserver(nil)
	t.Cleanup(func() { SetObserver(prev) })

	allocs := testing.AllocsPerRun(1000, func() {
		notify(OpCompare)
		notify(OpGenerate)
	})
	if allocs != 0 {
		t.Fatalf("notify with no observer allocated %v times per run, want 0", allocs)
	}
}

// TestAllocMeasureSeesSetObserverAllocation is the calibration for the test above:
// the one allocation the package doc admits to (SetObserver boxing its argument)
// must register, or a green "0 allocations" would just mean the measure is blind.
func TestAllocMeasureSeesSetObserverAllocation(t *testing.T) {
	prev := SetObserver(nil)
	t.Cleanup(func() { SetObserver(prev) })

	allocs := testing.AllocsPerRun(100, func() {
		SetObserver(func(Op) {})
	})
	if allocs < 1 {
		t.Fatalf("SetObserver registered %v allocations per run, want >= 1: the allocation measure cannot see allocations", allocs)
	}
}
