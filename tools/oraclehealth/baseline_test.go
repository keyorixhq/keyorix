package main

import "testing"

// TestCompareBaseline_BelowFailsEqualPasses is the required comparison proof: a
// baseline above the measured value must FAIL, and equal must PASS. Also pins that
// tolerance widens the floor and that a missing target fails closed.
func TestCompareBaseline_BelowFailsEqualPasses(t *testing.T) {
	rows := []baselineRow{
		{Target: "FuzzEqual", KillRate: 90, Tolerance: 0},
		{Target: "FuzzBelow", KillRate: 90, Tolerance: 0},
		{Target: "FuzzAbove", KillRate: 90, Tolerance: 0},
		{Target: "FuzzWithinTol", KillRate: 90, Tolerance: 10},
		{Target: "FuzzOutsideTol", KillRate: 90, Tolerance: 10},
		{Target: "FuzzMissing", KillRate: 50, Tolerance: 0},
	}
	measured := map[string]float64{
		"FuzzEqual":      90, // equal -> PASS
		"FuzzBelow":      89, // below, tol 0 -> FAIL
		"FuzzAbove":      95, // above -> PASS
		"FuzzWithinTol":  82, // 82 >= 90-10 -> PASS
		"FuzzOutsideTol": 79, // 79 < 90-10 -> FAIL
		// FuzzMissing absent -> FAIL
	}

	want := map[string]bool{
		"FuzzEqual": true, "FuzzBelow": false, "FuzzAbove": true,
		"FuzzWithinTol": true, "FuzzOutsideTol": false, "FuzzMissing": false,
	}

	results := compareBaseline(rows, measured)
	if len(results) != len(rows) {
		t.Fatalf("got %d results, want %d", len(results), len(rows))
	}
	for _, r := range results {
		if r.OK != want[r.Target] {
			t.Errorf("%s: OK=%v, want %v (measured=%.0f floor=%.0f reason=%q)",
				r.Target, r.OK, want[r.Target], r.Measured, r.Floor, r.Reason)
		}
	}
}

// TestCompareBaseline_ExactBoundary pins the >= semantics at the floor: measured
// exactly on the floor passes; one point under fails.
func TestCompareBaseline_ExactBoundary(t *testing.T) {
	rows := []baselineRow{{Target: "F", KillRate: 100, Tolerance: 15}} // floor = 85
	if got := compareBaseline(rows, map[string]float64{"F": 85}); !got[0].OK {
		t.Errorf("measured == floor should PASS, got FAIL: %s", got[0].Reason)
	}
	if got := compareBaseline(rows, map[string]float64{"F": 84}); got[0].OK {
		t.Error("measured one point below floor should FAIL, got PASS")
	}
}
