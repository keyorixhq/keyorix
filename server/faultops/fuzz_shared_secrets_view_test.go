// fuzz_shared_secrets_view_test.go: FuzzSharedSecretsViewNeverWrites targets
// GET /api/v1/users/{id}/shared-secrets (#2025, ListSharedSecretsForUser) — a
// read query, not a member of opCatalog's mutating-operation set (opCatalog
// keys must match inventory_registry_generated_test.go's knownOperations,
// which liveOperationKeys (dump_inventory_test.go) derives from
// mutatingHTTPMethods only, so a GET route can never be a catalog entry).
//
// Oracle, distinct from FuzzStorageFaultOperations' oracle (a): regardless of
// whether a fault makes the call succeed or fail, NO application-state table
// may ever change — a query has nothing to commit. AuditEvent is the one
// documented exception (ListSharedSecretsForUser's own admin cross-user-view
// branch calls writeAuditEvent on success and writeAuditEventFailed on a
// ceiling refusal, so an AuditEvent-only diff is expected on almost every
// run) — excluded via hashExcluding, the same helper
// fuzz_storage_fault_operations_test.go's oracle (a) AuditEvent-only carve-out
// uses, not a bespoke mechanism.
package faultops

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func decodeSharedSecretsViewFuzzOp(data []byte) (methodName string, nthCall int, kind faultstorage.FaultKind, ok bool) {
	methods := storageInterfaceMethodNames()
	if len(methods) == 0 {
		return "", 0, 0, false
	}
	b := func(i int) byte {
		if i < len(data) {
			return data[i]
		}
		return 0
	}
	methodIdx := (int(b(0))<<8 | int(b(1))) % len(methods)
	nth := 1 + int(b(2))%5
	kinds := []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
	kind = kinds[int(b(3))%len(kinds)]
	return methods[methodIdx], nth, kind, true
}

func FuzzSharedSecretsViewNeverWrites(f *testing.F) {
	seedFor := func(method string, nth int, kind byte) []byte {
		methods := storageInterfaceMethodNames()
		methodIdx := -1
		for i, m := range methods {
			if m == method {
				methodIdx = i
				break
			}
		}
		if methodIdx < 0 {
			return nil
		}
		return []byte{byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), kind}
	}
	// The route's own two guarded reads: ListSharedSecrets (the actual query)
	// and GetUser (the ceiling check's existence probe).
	if s := seedFor("ListSharedSecrets", 1, 0); s != nil {
		f.Add(s)
	}
	if s := seedFor("GetUser", 1, 0); s != nil {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		method, nth, kind, ok := decodeSharedSecretsViewFuzzOp(data)
		if !ok {
			t.Skip("empty storage method list")
		}
		ctx := context.Background()

		w := newFaultWorld(t, nil)
		targetID, err := createUserForFuzz(ctx, w, "fuzz-ssv-target")
		if err != nil {
			t.Skipf("setup CreateUser itself errored — not a fault-injection finding: %v", err)
		}
		// ShareSecret's owner gate (requireLiveOwnerAuthority, internal/core/
		// permissions.go) requires the sharer to be a LIVE member of the
		// secret's project — a check the RBAC admin-bypass every other
		// catalog Setup relies on does not satisfy on its own. The recipient
		// must independently be a project member too (sharing.go's
		// cross-project-grant guard for non-group shares).
		for _, uid := range []uint{1, targetID} {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects/1/members", map[string]any{
				"user_id": uid, "role": "project_admin",
			})
			if err != nil {
				t.Skipf("setup AddProjectMember(%d) itself errored — not a fault-injection finding: %v", uid, err)
			}
			if st/100 != 2 {
				t.Skipf("setup AddProjectMember(%d) itself failed — not a fault-injection finding: HTTP %d: %s", uid, st, body)
			}
		}
		secretID, err := createSecretForFuzz(ctx, w)
		if err != nil {
			t.Skipf("setup CreateSecret itself errored — not a fault-injection finding: %v", err)
		}
		shareStatus, shareBody, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID),
			map[string]any{"recipient_id": targetID, "permission": "read"})
		if err != nil {
			t.Skipf("setup ShareSecret itself errored — not a fault-injection finding: %v", err)
		}
		if shareStatus/100 != 2 {
			t.Skipf("setup ShareSecret itself failed — not a fault-injection finding: HTTP %d: %s", shareStatus, shareBody)
		}

		drainAllBackgroundGoroutines()
		before, err := snapshotDB(w.db)
		if err != nil {
			t.Fatalf("snapshotting pre-fault (post-setup) world: %v", err)
		}

		w.faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: kind, Err: errFuzzInjected})

		var status int
		var body []byte
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic escaped the transport layer entirely for ListSharedSecretsForUser (fault %s/%d/%s) — "+
						"the real Recovery middleware should have converted this to a 500, not let it unwind past the handler: %v",
						method, nth, kind, r)
				}
			}()
			status, body, err = httpJSON(ctx, w, http.MethodGet, fmt.Sprintf("/api/v1/users/%d/shared-secrets", targetID), nil)
		}()
		if err != nil {
			t.Fatalf("GET shared-secrets returned a transport error (not an application error) for fault %s/%d/%s: %v", method, nth, kind, err)
		}

		if !w.faulty.Fired() {
			return // NthCall exceeded the real call count — not interesting for this input.
		}

		drainAllBackgroundGoroutines()
		after, err := snapshotDB(w.db)
		if err != nil {
			t.Fatalf("snapshotting post-fault world: %v", err)
		}

		if hashExcluding(before, "AuditEvent") != hashExcluding(after, "AuditEvent") {
			t.Errorf("ORACLE VIOLATION — a read-only GET (HTTP %d: %s) changed non-audit application state under "+
				"fault %s/%d/%s. Differing tables: %v", status, body, method, nth, kind, diffTables(before, after))
		}
	})
}
