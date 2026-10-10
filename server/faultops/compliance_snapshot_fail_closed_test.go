// compliance_snapshot_fail_closed_test.go -- regression guard for #2834.
//
// POST /api/v1/compliance/snapshots used to persist a CompliancePostureSnapshot
// row with partial counts and report success when a posture sub-rollup read
// failed (oracle (a): reported success, final state differs from the fault-free
// reference run). It now fails closed: any degraded sub-rollup -> error response,
// no row. The two knownOpenTolerances entries that covered this are gone, so
// these tuples run with NO tolerance.
//
// The inputs are addressed by (op key, method name), resolved at run time, so
// unlike a committed legacy-index seed they cannot drift when opCatalog or the
// storage method set changes.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func legacyFuzzInputFor(t *testing.T, opKey, method string, nth int, kind faultstorage.FaultKind) []byte {
	t.Helper()
	opIdx := -1
	for i, op := range opCatalog {
		if op.Key == opKey {
			opIdx = i
			break
		}
	}
	if opIdx < 0 {
		t.Fatalf("op %q is not in opCatalog", opKey)
	}
	methodIdx := -1
	for i, m := range storageInterfaceMethodNames() {
		if m == method {
			methodIdx = i
			break
		}
	}
	if methodIdx < 0 {
		t.Fatalf("storage method %q not found", method)
	}
	kindIdx := -1
	for i, k := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError} {
		if k == kind {
			kindIdx = i
		}
	}
	data := []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), byte(kindIdx)}
	// Self-check: the bytes must decode back to the tuple we meant (opIdx and
	// methodIdx are taken modulo the catalog/method counts).
	d, ok := decodeFuzzOp(data)
	if !ok || opCatalog[d.opIndex].Key != opKey || d.methodName != method || d.nthCall != nth || d.kind != kind {
		t.Fatalf("encoded input %x does not round-trip to (%q,%q,%d,%s): got %+v", data, opKey, method, nth, kind, d)
	}
	return data
}

func TestComplianceSnapshotFailsClosed_2834(t *testing.T) {
	const op = "REST POST /api/v1/compliance/snapshots"
	for _, method := range []string{
		"CountDynamicSecretConfigsByClassification", // the original #2834 report
		"ListRotationPolicies",                      // the sibling found on #2969
	} {
		t.Run(method, func(t *testing.T) {
			data := legacyFuzzInputFor(t, op, method, 1, faultstorage.KindError)
			t.Log(traceFuzzOp(data))
			runOneFuzzIteration(t, data)
		})
	}
}
