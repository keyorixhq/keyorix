package http

// soak_latency_drift_test.go -- calibration of the soak's latency oracle
// (checkLatencyDrift) on both sides: a single slow sample must not fail a run,
// a drift that lasts must (#4389).

import (
	"fmt"
	"testing"
	"time"
)

// driftRecorder keeps what the oracle reports instead of failing the test.
type driftRecorder struct {
	testing.TB
	errs []string
}

func (r *driftRecorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *driftRecorder) Helper() {}

func driftSamples(ms ...int) []soakSample {
	ss := make([]soakSample, len(ms))
	for i, m := range ms {
		ss[i] = soakSample{ops: i * 150, probeP95: time.Duration(m) * time.Millisecond}
	}
	return ss
}

func TestSoakLatencyDriftOracle_Calibration(t *testing.T) {
	cases := []struct {
		name    string
		samples []soakSample
		wantErr bool
	}{
		// The growth table of queue run 44022419994 (probe p95 in ms at ops 0..1500).
		// Only the last sample was slow: the oracle compared the larger of the last
		// two samples with the larger of the first two and failed at 141 vs 24 ms.
		{"one slow last sample, as in the queue run", driftSamples(24, 24, 26, 23, 23, 23, 26, 23, 52, 23, 141), false},
		{"one slow early sample", driftSamples(141, 24, 26, 23, 23, 23, 26, 23, 24, 23, 24), false},
		{"flat", driftSamples(24, 24, 24, 24, 24, 24, 24, 24), false},
		// A latency that keeps growing is what the oracle is for.
		{"sustained growth over the last third", driftSamples(24, 24, 26, 23, 23, 24, 25, 60, 110, 120, 130), true},
		{"steady climb", driftSamples(20, 30, 45, 60, 80, 100, 120, 140, 160, 180, 200), true},
		{"too few samples to judge", driftSamples(24, 900, 900), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &driftRecorder{TB: t}
			checkLatencyDrift(r, tc.samples)
			if got := len(r.errs) > 0; got != tc.wantErr {
				t.Fatalf("drift reported = %v (%v), want %v", got, r.errs, tc.wantErr)
			}
		})
	}
}
