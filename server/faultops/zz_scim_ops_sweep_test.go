package faultops

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

// scimSweepOps are the SCIM ops swept on EVERY default run (SCIM-TAILS-1), not only
// when KEYORIX_FAULTOPS_SWEEP_OPS names them. Add an op here when it is driven by the
// catalog and passes TestOpFaultSweep.
var scimSweepOps = []string{
	"REST PUT /scim/v2/Groups/{id}",
	"REST PATCH /scim/v2/Groups/{id}",
	"REST DELETE /scim/v2/Groups/{id}",
	// Item 3: the ops SESSION-AT AT5 left StatusPending (zz_scim_ops_catalog_test.go).
	"REST POST /scim/v2/Groups",
	"REST POST /scim/v2/Users",
	"REST PUT /scim/v2/Users/{id}",
	"REST PATCH /scim/v2/Users/{id}",
	"REST DELETE /scim/v2/Users/{id}",
}

// TestSCIMOpsFaultSweep is TestOpFaultSweep for scimSweepOps, cheap enough for the
// default run: instead of every storage method (7125 inputs per op, minutes), it runs
// the op once unfaulted, records which storage methods Execute calls and how often, and
// sweeps exactly those (call 1..min(count, 5) × every fault kind) through the fuzzer's
// own iteration body and oracles. A fault on a method the op never calls cannot fire,
// so the skipped inputs are the ones TestOpFaultSweep discards as "fault did not fire".
//
// Why it exists: ReplaceSCIMGroup/PatchSCIMGroup re-read the group after the commit and
// reported a re-read failure as if the write had failed (oracle (a): error response,
// state changed). Only the sweep reaches that call; the fuzzer picks the op from one
// byte of ~300.
func TestSCIMOpsFaultSweep(t *testing.T) {
	methods := storageInterfaceMethodNames()
	ref := buildReusableFaultWorld(t, nil)
	w := buildReusableFaultWorld(t, nil)
	for _, key := range scimSweepOps {
		opIdx := slices.IndexFunc(opCatalog, func(o operation) bool { return o.Key == key })
		if opIdx < 0 || opIdx > 255 {
			t.Fatalf("op %q not addressable by one fuzz byte (index %d)", key, opIdx)
		}
		counts := probeExecuteCalls(t, w, opCatalog[opIdx])
		if len(counts) == 0 {
			t.Fatalf("op %q: the unfaulted run called no storage method", key)
		}
		fired, total := 0, 0
		for mi, name := range methods {
			n := min(counts[name], 5)
			for nth := 1; nth <= n; nth++ {
				for kind := range 3 {
					total++
					data := []byte{byte(opIdx), byte(mi >> 8), byte(mi), byte(nth - 1), byte(kind)}
					t.Run(fmt.Sprintf("%s/%x", key, data), func(t *testing.T) {
						runOneFuzzIterationWithWorlds(t, data, ref, w, func(oracleInput) { fired++ })
					})
				}
			}
		}
		if fired == 0 {
			t.Fatalf("op %q: none of the %d probed inputs fired a fault, the sweep checks nothing", key, total)
		}
		t.Logf("SWEEP %s: %d of %d probed inputs fired a fault and were checked by the oracles", key, fired, total)
	}
}

// probeExecuteCalls runs op unfaulted in w (Setup, then Execute) and returns how many
// times Execute called each storage method.
func probeExecuteCalls(t *testing.T, w *faultWorld, op operation) map[string]int {
	t.Helper()
	ctx := context.Background()
	w.resetForReuse(t, nil)
	var state any
	if op.Setup != nil {
		var err error
		if state, err = op.Setup(ctx, w); err != nil {
			t.Fatalf("op %q: setup: %v", op.Key, err)
		}
	}
	drainAllBackgroundGoroutines()
	from := len(w.faulty.Calls())
	res, err := op.Execute(ctx, w, state)
	if err != nil {
		t.Fatalf("op %q: execute: %v", op.Key, err)
	}
	if !res.Success {
		t.Fatalf("op %q: the unfaulted run failed: %s", op.Key, res.Detail)
	}
	drainAllBackgroundGoroutines()
	counts := map[string]int{}
	for _, c := range w.faulty.Calls()[from:] {
		counts[c.Method]++
	}
	return counts
}
