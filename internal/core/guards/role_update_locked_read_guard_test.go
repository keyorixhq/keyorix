package guards

import "testing"

// TestUpdateRole_ClassifiesFromALockedRead pins #3919 structurally, on every
// backend: inside its transactions UpdateRole reads the role it classifies (the
// assignable-scope widening and the audit text) through tx.LockRoleForUpdate
// (FOR UPDATE on PostgreSQL), before tx.UpdateRole writes it, and never through
// an unlocked tx.GetRole. A plain in-transaction read locks nothing under READ
// COMMITTED, so a concurrent scope change could commit between the
// classification and the write. The write itself is in updateRoleTx, which only
// UpdateRole's transactions call. Sibling of
// TestUpdateSharePermission_ClassifiesFromALockedRead (SHARE-CAS-1).
//
// What it does not check: that the lock is taken by the storage (that is
// TestLockRoleForUpdate_DialectMatchedLocking in internal/storage/store) or that
// it serializes two replicas (the pg-gated
// TestCTAReview_UpdateRoleExplicitScope_vs_NarrowScope_CrossReplicaPostgres).
func TestUpdateRole_ClassifiesFromALockedRead(t *testing.T) {
	locks, writes := 0, 0
	for _, c := range columnScopedFuncCalls(t, "../rbac_roles.go", "KeyorixCore", "UpdateRole") {
		switch {
		case c.Recv == "tx" && c.Name == "GetRole":
			t.Errorf("UpdateRole reads the role with tx.GetRole: an unlocked read cannot hold its classification until the write")
		case c.Recv == "tx" && c.Name == "LockRoleForUpdate":
			locks++
		case c.Name == "updateRoleTx":
			writes++
		}
	}
	// One locked read per transaction: commit 1 (owed) and commit 2 (widening).
	if locks < 2 {
		t.Errorf("UpdateRole calls tx.LockRoleForUpdate %d time(s), want one in each of its two transactions", locks)
	}
	if writes < 2 {
		t.Fatalf("UpdateRole calls updateRoleTx %d time(s), want 2: update this guard with the new write", writes)
	}
}
