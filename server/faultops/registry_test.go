// registry_test.go is the additive registration API for FuzzStorageFaultOperations'
// operation catalog and the inventory overrides (C-MERGE-FRICTION).
//
// Why: opcatalog_test.go's opCatalog literal and inventory_overrides_test.go's
// operationOverrides literal are each one shared table that every op-adding PR
// appends to — two such PRs always conflict, and the merge queue serialises
// them. A new operation now lives in its OWN file, ops_<area>_test.go:
//
//	func init() {
//		registerOps("saml", operation{Key: "REST POST /auth/saml/acs", ...})
//		registerOverrides("saml", map[string]overrideEntry{
//			"REST POST /auth/saml/acs": {StatusFuzzed, "opCatalog[...] — ops_saml_test.go"},
//		})
//	}
//
// The legacy tables are untouched and still authoritative for what they hold.
//
// How it merges:
//   - registerOverrides writes straight into operationOverrides, so statusOf,
//     TestOperationCatalogKeysAreRegistered's reverse direction and
//     TestReportOperationTableCoverage see registered entries with no change
//     to inventory_overrides_test.go. A key already present (legacy or
//     another area) is NOT overwritten; it is recorded and
//     TestRegisteredCatalog_NoDuplicateKeys fails.
//   - registerOps only STAGES operations. TestMain (main_test.go) calls
//     finalizeRegisteredOps once, after every init() has run, which appends
//     them to opCatalog AFTER every legacy entry (opcatalog_test.go's literal
//     plus any init()-time appends such as webauthn_finish_ops_test.go's),
//     ordered by area name, then by registration order within the area. This
//     is deliberate: the legacy seed format addresses an op by
//     `data[0] % len(opCatalog)` (see opcatalog_corpus_pin_test.go), so a
//     registered op must never shift a legacy op's index. Staging, rather
//     than appending from each file's init(), keeps the order independent of
//     Go's per-file init order (ops_*.go would otherwise init BEFORE
//     webauthn_finish_ops_test.go and shift its ops).
//
// What this does NOT guarantee: a NEW area whose name sorts before an
// existing registered area still shifts that area's ops' indices (they are
// all after the legacy block, so legacy seeds are safe; seeds that address a
// REGISTERED op by legacy index are not). The fix for that is addressing ops
// by key, not index — the v2 seed format, a separate change.
package faultops

import (
	"fmt"
	"sort"
	"sync"
	"testing"
)

type registeredOp struct {
	area string
	seq  int
	op   operation
}

var (
	registryMu          sync.Mutex
	registeredOps       []registeredOp
	registryFinalized   bool
	overrideCollisions  []string // "<key>: <area> collides with <previous owner>"
	overrideOwnerByArea = map[string]string{}
)

// registerOps stages ops for the catalog under area. Call it from an init()
// in ops_<area>_test.go. Calling it after finalizeRegisteredOps panics: an op
// registered that late would silently never be fuzzed.
func registerOps(area string, ops ...operation) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if registryFinalized {
		panic(fmt.Sprintf("faultops: registerOps(%q) after finalizeRegisteredOps — register from an init() only", area))
	}
	if area == "" {
		panic("faultops: registerOps with an empty area")
	}
	for _, op := range ops {
		registeredOps = append(registeredOps, registeredOp{area: area, seq: len(registeredOps), op: op})
	}
}

// registerOverrides adds per-area inventory classifications to
// operationOverrides. Existing keys are never overwritten (see the file
// comment); a collision fails TestRegisteredCatalog_NoDuplicateKeys.
func registerOverrides(area string, entries map[string]overrideEntry) {
	registryMu.Lock()
	defer registryMu.Unlock()
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, exists := operationOverrides[k]; exists {
			owner := overrideOwnerByArea[k]
			if owner == "" {
				owner = "inventory_overrides_test.go"
			} else {
				owner = "area " + owner
			}
			overrideCollisions = append(overrideCollisions, fmt.Sprintf("%q: area %s collides with %s", k, area, owner))
			continue
		}
		operationOverrides[k] = entries[k]
		overrideOwnerByArea[k] = area
	}
}

// finalizeRegisteredOps appends every staged op to opCatalog, after all
// legacy entries, in (area, registration order). Idempotent.
func finalizeRegisteredOps() {
	registryMu.Lock()
	defer registryMu.Unlock()
	if registryFinalized {
		return
	}
	registryFinalized = true
	staged := append([]registeredOp(nil), registeredOps...)
	sort.SliceStable(staged, func(i, j int) bool {
		if staged[i].area != staged[j].area {
			return staged[i].area < staged[j].area
		}
		return staged[i].seq < staged[j].seq
	})
	for _, r := range staged {
		opCatalog = append(opCatalog, r.op)
	}
}

// catalogDuplicateKeys returns every op key that appears more than once in
// cat, as "key (indices i, j, ...)".
func catalogDuplicateKeys(cat []operation) []string {
	idx := map[string][]int{}
	for i, op := range cat {
		idx[op.Key] = append(idx[op.Key], i)
	}
	var dups []string
	for k, is := range idx {
		if len(is) > 1 {
			dups = append(dups, fmt.Sprintf("%q (indices %v)", k, is))
		}
	}
	sort.Strings(dups)
	return dups
}

// TestRegisteredCatalog_NoDuplicateKeys: the merged catalog (legacy table +
// init()-time appends + registered ops) holds every key at most once, and no
// registered override collided with an existing one. A duplicate op key
// would make the fuzzer drive one route twice while the ratchet counts it
// once; a colliding override would silently lose one area's classification.
func TestRegisteredCatalog_NoDuplicateKeys(t *testing.T) {
	if !registryFinalized {
		t.Fatal("finalizeRegisteredOps has not run — TestMain (main_test.go) must call it before m.Run, " +
			"or registered ops are never fuzzed")
	}
	if dups := catalogDuplicateKeys(opCatalog); len(dups) > 0 {
		t.Errorf("opCatalog (legacy + registered) holds duplicate key(s) — each operation must be registered once:\n  %v", dups)
	}
	if len(overrideCollisions) > 0 {
		t.Errorf("registerOverrides collided with existing entries (not overwritten, so one classification was dropped):\n  %v", overrideCollisions)
	}
	t.Logf("opCatalog: %d ops, %d of them registered via registerOps", len(opCatalog), len(registeredOps))
}

// TestRegistry_Calibration exercises the registry against a scratch catalog
// and override map, so the red paths are proven without touching the real
// package state: duplicate op keys are found across a legacy/registered
// boundary, override collisions are recorded and do not overwrite, and
// registered ops land after every legacy op in (area, seq) order.
func TestRegistry_Calibration(t *testing.T) {
	// Swap the package state for scratch copies, restore afterwards.
	registryMu.Lock()
	saveCat, saveOps, saveFin := opCatalog, registeredOps, registryFinalized
	saveOv, saveColl, saveOwner := operationOverrides, overrideCollisions, overrideOwnerByArea
	opCatalog = []operation{{Key: "L1"}, {Key: "L2"}}
	registeredOps, registryFinalized = nil, false
	operationOverrides = map[string]overrideEntry{"L1": {StatusFuzzed, "legacy"}}
	overrideCollisions, overrideOwnerByArea = nil, map[string]string{}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		opCatalog, registeredOps, registryFinalized = saveCat, saveOps, saveFin
		operationOverrides, overrideCollisions, overrideOwnerByArea = saveOv, saveColl, saveOwner
		registryMu.Unlock()
	})

	registerOps("zeta", operation{Key: "Z1"}, operation{Key: "Z2"})
	registerOps("alpha", operation{Key: "A1"})
	registerOps("zeta", operation{Key: "L2"}) // duplicates a legacy key
	registerOverrides("alpha", map[string]overrideEntry{"A1": {StatusFuzzed, "a"}, "L1": {StatusExcluded, "clobber attempt"}})
	registerOverrides("zeta", map[string]overrideEntry{"A1": {StatusExcluded, "clobber attempt"}})
	finalizeRegisteredOps()

	var got []string
	for _, op := range opCatalog {
		got = append(got, op.Key)
	}
	want := []string{"L1", "L2", "A1", "Z1", "Z2", "L2"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("merged order = %v, want %v (legacy first, then area-sorted, then registration order)", got, want)
	}
	if dups := catalogDuplicateKeys(opCatalog); len(dups) != 1 {
		t.Errorf("want exactly the L2 duplicate reported, got %v", dups)
	}
	if len(overrideCollisions) != 2 {
		t.Errorf("want 2 override collisions (L1 vs legacy, A1 vs area alpha), got %v", overrideCollisions)
	}
	if operationOverrides["L1"].Note != "legacy" || operationOverrides["A1"].Note != "a" {
		t.Errorf("a colliding registerOverrides call overwrote an existing entry: %+v", operationOverrides)
	}
	if catalogDuplicateKeys([]operation{{Key: "x"}, {Key: "y"}}) != nil {
		t.Error("catalogDuplicateKeys reported a duplicate in a duplicate-free catalog")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("registerOps after finalizeRegisteredOps must panic, not silently drop the op")
			}
		}()
		registerOps("late", operation{Key: "LATE"})
	}()
}
