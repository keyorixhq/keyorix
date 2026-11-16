package middleware

// resguard_authcache_test.go — PK1 port of FuzzAuthCacheDifferential onto the
// shared resguard resource layer (part 2: authz CPU/alloc — the bcrypt-storm #119
// class). Each fuzzed op-program is metered for allocation (fatal, per-byte slope:
// more ops -> more work) and CPU/wall (advisory) against a calibrated budget. The
// existing differential oracles inside acRunOp are UNCHANGED.
//
// What this oracle does NOT verify: correctness; alloc sampled (1-in-32 + slow);
// CPU advisory/process-wide (so a pure CPU/bcrypt storm is reported, not failed —
// the test harness's own deadlines are the fatal backstop); alloc is process-wide
// across the two compared arms (not separable).

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const authcacheBudgetPath = "testdata/resguard-authcache-differential.json"

func authcacheResguardProbe(f *testing.F) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(authcacheBudgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", authcacheBudgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

// authcacheBenignPrograms mirror the FuzzAuthCacheDifferential f.Add seeds: valid
// op sequences exercising login/PAT/machine-token/revoke/suspend/role paths.
func authcacheBenignPrograms() [][]byte {
	return [][]byte{
		{0, 10, 1, 10, 2, 10, 3, 10, 4, 10, 5, 10, 6, 10, 7, 10, 8, 10, 9, 10, 11},
		{0, 10, 9, 10, 3, 10},
		{0, 10, 6, 10, 6, 10},
		{1, 10, 4, 10},
		{2, 10, 5, 10},
		{0, 11, 10},
		{2, 12, 5, 12},
		{2, 12, 7, 12, 7, 12},
	}
}

func calibrateAuthcache(t *testing.T) resguard.Budget {
	t.Helper()
	w := acBuildWorld(t)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	var costs []resguard.Cost
	for range 2 {
		for _, program := range authcacheBenignPrograms() {
			st := w.resetIteration(t)
			maxOps := min(len(program), 48)
			costs = append(costs, probe.Measure(len(program), func() {
				for i := range maxOps {
					acRunOp(t, w, st, program[i])
				}
			}))
		}
	}
	b := resguard.Calibrate("authcache_differential", costs, resguard.DefaultFactor)
	b.KeepOnly("alloc_bytes", "mallocs", "cpu_ns", "wall_ns")
	return b
}

func TestResguardAuthcacheCalibrate(t *testing.T) {
	b := calibrateAuthcache(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(authcacheBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", authcacheBudgetPath, b.Summary())
	}
}

// TestResguardAuthcacheRedGreen — committed red/green for the authcache memory
// oracle: a benign op-program passes; the same cost with a storm-sized allocation
// trips the budget naming alloc_bytes.
func TestResguardAuthcacheRedGreen(t *testing.T) {
	b := calibrateAuthcache(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	w := acBuildWorld(t)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	program := authcacheBenignPrograms()[3]
	st := w.resetIteration(t)
	maxOps := min(len(program), 48)
	green := probe.Measure(len(program), func() {
		for i := range maxOps {
			acRunOp(t, w, st, program[i])
		}
	})
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign op-program (alloc=%d) must pass the budget", green.AllocBytes)
	}
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
