package faultops

import (
	"sort"
	"testing"
)

// TestOperationTableRatchet fails the moment the live server's mutating REST/
// system/gRPC surface diverges from the checked-in registry
// (inventory_registry_generated_test.go) in EITHER direction: a new route/method
// added without regenerating (and committing) the registry, or a stale entry
// left behind after one was removed. This is the guard GOAL's STEP 0 asked for:
// "a new mutating route or gRPC method without an entry ... fails the test."
//
// It deliberately does NOT require every key to be StatusFuzzed — only that
// every live key has SOME accounted-for entry. A key with no override defaults
// to StatusPending (see inventory_overrides_test.go), which is a legitimate,
// visible state, not a pass-through: TestReportOperationTableCoverage below
// prints the Pending count on every run so it can never quietly grow unnoticed.
func TestOperationTableRatchet(t *testing.T) {
	live := liveOperationKeys(t)

	liveSet := make(map[string]bool, len(live))
	for _, k := range live {
		liveSet[k] = true
	}

	var newKeys []string
	for _, k := range live {
		if !knownOperations[k] {
			newKeys = append(newKeys, k)
		}
	}
	var staleKeys []string
	for k := range knownOperations {
		if !liveSet[k] {
			staleKeys = append(staleKeys, k)
		}
	}
	sort.Strings(newKeys)
	sort.Strings(staleKeys)

	if len(newKeys) > 0 {
		t.Errorf("%d mutating operation(s) exist on the live server but are NOT in the registry — "+
			"run REGEN_INVENTORY=1 go test ./server/faultops/... -run TestRegenerateInventoryRegistry, "+
			"commit the diff, and classify each new key in inventory_overrides_test.go "+
			"(StatusPending is fine as an honest default, StatusExcluded needs a reason): %v", len(newKeys), newKeys)
	}
	if len(staleKeys) > 0 {
		t.Errorf("%d registry key(s) no longer correspond to a live mutating operation — "+
			"regenerate the registry and remove any now-unneeded inventory_overrides_test.go entries: %v",
			len(staleKeys), staleKeys)
	}
}

// TestReportOperationTableCoverage is not a pass/fail gate — it logs the
// Fuzzed/Pending/Excluded breakdown on every run so coverage expansion (or
// silent stagnation) is visible without reading inventory_overrides_test.go by
// hand. Matches CLAUDE.md's "no silent caps: log what was dropped."
func TestReportOperationTableCoverage(t *testing.T) {
	var fuzzed, pending, excluded []string
	for k := range knownOperations {
		switch statusOf(k).Status {
		case StatusFuzzed:
			fuzzed = append(fuzzed, k)
		case StatusExcluded:
			excluded = append(excluded, k)
		default:
			pending = append(pending, k)
		}
	}
	t.Logf("operation table coverage: %d total, %d fuzzed, %d excluded, %d pending",
		len(knownOperations), len(fuzzed), len(excluded), len(pending))
}
