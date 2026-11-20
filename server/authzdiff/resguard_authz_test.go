package authzdiff

// resguard_authz_test.go — PK1 port of FuzzAuthzDiff onto the shared resguard
// resource layer (part 2 of the brief: the authz targets, CPU/alloc — the
// bcrypt-storm #119 class). Each fuzzed authz comparison (runCase) is metered for
// allocation (fatal) and CPU/wall (advisory) against a calibrated ABSOLUTE ceiling:
// the cost of one authz decision is a fixed-shape quantity, not proportional to an
// input size, so AbsMax is the right model.
//
// NOTE on the bcrypt storm: this package's TestMain lowers the bcrypt work factor
// to MinCost (a core test hook), so a login-heavy path is cheap here by design;
// the resguard CPU/wall meters are ADVISORY (process-wide, never fatal — they
// false-fire under shared-host load), so a genuine bcrypt storm surfaces as an
// advisory line in the failure message, while the fatal signal PK1 adds is
// allocation. The existing differential oracles (UNCALIBRATED/UNEXPLAINED) are
// unchanged. What this oracle does NOT verify: it does not make CPU fatal (so a
// pure CPU storm at production bcrypt cost is reported, not failed — the wall
// deadline of the surrounding test harness is the fatal backstop); alloc is
// sampled; alloc is process-wide (not separable between the two compared backends).

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// authzNominalInputLen is the stand-in input size for the 7 scalar fuzz selectors
// (AbsMax ignores it; it only affects the never-used slope term).
const authzNominalInputLen = 8

const authzBudgetPath = "testdata/resguard-authz-diff.json"

func authzResguardProbe(f *testing.F) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(authzBudgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", authzBudgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

// authzCalibrateFactor is the slack over p99 used by calibrateAuthz. Raised
// from DefaultFactor (4.0) to 5.0 because calibrateAuthz covers only the
// allowed paths (allPerms mask), while the fuzz target's hardcoded seed#0
// uses mask=0xff which consistently hits a "denied" code path ~4.4× the
// allowed-path p99 (confirmed: mallocs=323883, factor-4 abs_max=292652).
// The factor is the documented knob; the ceiling is still derived from
// measured p99 × factor, never hand-picked.
const authzCalibrateFactor = 5.0

// calibrateAuthz drives benign (valid) authz comparisons across the ops × principal
// matrix with the default route/scope/arg, under a SampleEvery=1 probe, and takes
// the absolute p99·factor ceiling on alloc/mallocs.
//
// What calibrateAuthz does NOT measure: denial-path variations (mask != allPerms)
// and secondary targets (target[1+]). The factor accounts for denial-path overhead.
func calibrateAuthz(t *testing.T) resguard.Budget {
	t.Helper()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	specs := withDerived(t, ops())
	var costs []resguard.Cost
	for si := range len(specs) {
		spec := specs[si]
		tg := spec.targets[0]
		for _, pk := range allPrincipalKinds {
			v := defaultVariation
			if pk == pkCustom || pk == pkMachine {
				s := genScopes(tg)[0]
				route := "user"
				if pk == pkMachine {
					route = "machine"
					if s == "global" {
						s = "A"
					}
				}
				v = variation{Mask: allPerms, Route: route, Scope: s}
			}
			if spec.invalidArg != nil && spec.invalidArg(tg, 0) {
				continue
			}
			k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: 0, variation: v}
			costs = append(costs, probe.Measure(authzNominalInputLen, func() { runCase(t, spec, k, tg) }))
		}
	}
	b := resguard.Calibrate("authz_diff", costs, authzCalibrateFactor)
	b.KeepOnly("alloc_bytes", "mallocs", "cpu_ns", "wall_ns")
	b.UseAbsolute("alloc_bytes", "mallocs")
	return b
}

func TestResguardAuthzCalibrate(t *testing.T) {
	b := calibrateAuthz(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(authzBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", authzBudgetPath, b.Summary())
	}
}

// TestResguardAuthzRedGreen — committed red/green for the authz memory oracle.
// GREEN: a benign measured authz comparison passes. RED: the same cost with the
// allocation scaled to a storm (the shape of a bug that drove many hashes/objects)
// trips the absolute budget naming alloc_bytes.
func TestResguardAuthzRedGreen(t *testing.T) {
	b := calibrateAuthz(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	specs := withDerived(t, ops())
	spec := specs[0]
	tg := spec.targets[0]
	k := caseKey{Op: spec.name, Principal: allPrincipalKinds[0], Target: tg.String(), Arg: 0, variation: defaultVariation}
	green := probe.Measure(authzNominalInputLen, func() { runCase(t, spec, k, tg) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign authz comparison (alloc=%d) must pass the budget", green.AllocBytes)
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
