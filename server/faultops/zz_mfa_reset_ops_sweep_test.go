package faultops

import (
	"fmt"
	"slices"
	"testing"
)

// TestMFAResetOpsFaultSweep is TestSCIMOpsFaultSweep for mfaResetOps (oracle (g)
// and the fuzzer's other oracles): each op is run once unfaulted to learn which
// storage methods Execute calls and how often, then every (method, call 1..5,
// fault kind) is injected through the fuzzer's own iteration body.
func TestMFAResetOpsFaultSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive sweep; run without -short")
	}
	methods := storageInterfaceMethodNames()
	ref := buildReusableFaultWorld(t, nil)
	w := buildReusableFaultWorld(t, nil)
	for _, key := range mfaResetOps {
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
