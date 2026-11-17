// seed_4025_ceiling_snapshot_read_test.go — the committed seed for the admin-rank
// ceiling's one-statement read of the target's grants (#4025).
//
// #4025 added ListUserRoleGrants as the ceiling's second target read; GetUserRoleScopes
// stays its first, so 3093_grpc_updateuser_getuserrolescopes_nth2_error still targets
// what it was written for (call #1 the ceiling, call #2 projectCounts' enrichment) and
// is kept unchanged. The new seed covers the new read.
package faultops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// TestSeed4025_UpdateUserCeilingGrantListingFaultFailsClosed: the seed decodes to
// (gRPC UpdateUser, ListUserRoleGrants, 1, error), the fault fires inside the ceiling,
// and every oracle accepts the outcome without an exemption row: the update is refused
// and leaves nothing behind.
func TestSeed4025_UpdateUserCeilingGrantListingFaultFailsClosed(t *testing.T) {
	const (
		seed   = "4025_grpc_updateuser_listuserrolegrants_error"
		op     = "GRPC keyorix.v1.UserService.UpdateUser"
		method = "ListUserRoleGrants"
	)
	if _, err := os.Stat(filepath.Join(fuzzCorpusDir, seed)); err != nil {
		t.Fatalf("seed %s is not committed: %v", seed, err)
	}
	d, ok := decodeFuzzOpV2(readFuzzCorpusFile(t, filepath.Join(fuzzCorpusDir, seed)))
	if !ok || opCatalog[d.opIndex].Key != op || d.methodName != method || d.nthCall != 1 || d.kind != faultstorage.KindError {
		t.Fatalf("seed %s decodes to %+v (ok=%v), want (%q, %s, 1, error)", seed, d, ok, op, method)
	}
	in, outcome, reason := driveFaultCase(t, op, method, 1, faultstorage.KindError)
	if outcome != driveObserved {
		t.Fatalf("case could not be driven (%s: %s): the ceiling no longer reads %s for the target", outcome, reason, method)
	}
	if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) > 0 {
		t.Fatalf("a fault on the ceiling's grant listing must fail closed with no effect; the oracle reports: %v", f)
	}
}
