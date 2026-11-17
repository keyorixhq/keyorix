package mongofuzz

import "testing"

// TestAllocOverBudget pins oracle (a)'s arithmetic in both directions: churn that
// is fully explained by dials is within budget, and an allocation beyond the
// ceiling is over budget whether or not the interaction also churned.
func TestAllocOverBudget(t *testing.T) {
	const churnDials = 12_000 // KFZ-2026-130 on a fast host: 10k-12.6k dials in 0.7 s
	cases := []struct {
		name  string
		delta uint64
		dials int64
		over  bool
	}{
		{"no dials, at ceiling", allocCeiling, 0, false},
		{"no dials, one byte over ceiling", allocCeiling + 1, 0, true},
		{"2 dials, planted 40 MB amplification", 40<<20 + 2*perDialAlloc, 2, true},
		{"measured KFZ-2026-130 churn (10.5 KB per dial)", churnDials * 10_510, churnDials, false},
		{"churn plus 64 MB planted amplification", churnDials*10_510 + 64<<20, churnDials, true},
		{"negative dials treated as zero", allocCeiling + 1, -5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if over, bound := allocOverBudget(tc.delta, tc.dials); over != tc.over {
				t.Fatalf("allocOverBudget(%d, %d) over=%v bound=%d, want over=%v", tc.delta, tc.dials, over, bound, tc.over)
			}
		})
	}
}

// TestKFZ2026130ReconnectChurnWithinBudget replays the KFZ-2026-130 crasher
// (mode 0, honest framing, ping, body "20000"). The malformed hello makes the
// heartbeat monitor reconnect in a tight loop; the old fixed 32 MiB and the
// 73 MB "48 MB read buffer" bounds both failed it (5/5 on a fast host). Repeated
// so a host-speed-dependent pass cannot hide a flaky budget.
func TestKFZ2026130ReconnectChurnWithinBudget(t *testing.T) {
	for range 10 {
		runInteraction(t, 0, 0, 44, 0, []byte("20000"))
	}
}
