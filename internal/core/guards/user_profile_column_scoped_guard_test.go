package guards

import "testing"

// TestUserProfileWrites_AreColumnScoped pins the #2653/#2654 fix structurally:
// UpdateUser (admin edit) and UpdateOwnProfile (self-service edit) must persist
// only the profile columns they own, through
// LocalStorage.UpdateUserIfActiveStateMatches's column-scoped conditional
// UPDATE — never the full pre-read row, which reverted a concurrent
// SuspendUser / ChangePassword / MFA / lockout write. The Postgres race tests
// (TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres,
// TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres,
// TestCTAReview_UserRowNarrow_*) prove the behaviour where a DSN exists, and
// their SQLite twins (TestUserRowNarrow_*) in default CI; this runs everywhere.
//
// Hops checked: UpdateOwnProfile -> c.UpdateUser (core) ->
// storage/tx.UpdateUserIfActiveStateMatches -> its LocalStorage body. It does
// not check SCIM's callers of the same storage method (they get the same
// column scoping from the storage body, which is what this asserts).
func TestUserProfileWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_users.go", "UpdateUserIfActiveStateMatches")
	assertCoreWritesOnlyVia(t, "../users.go", "UpdateUser", "tx", "UpdateUserIfActiveStateMatches", "UpdateUser", "Save")
	assertCoreWritesOnlyVia(t, "../account.go", "UpdateOwnProfile", "c", "UpdateUser", "UpdateUser", "Save", "UpdateUserIfActiveStateMatches")
}

// TestUpdateUserWrites_AreBuiltFromALockedRead pins the FIX-USER-ROW-NARROW-1
// half of #2653/#2654: the column scoping above still wrote username/email from
// UpdateUser's unlocked GetUser, reverting a concurrent rename or email change.
// Every conditional profile write in UpdateUser must now be preceded, in its
// transaction, by its own tx.LockUserForUpdate re-read that the write is built
// from. What this checks: the counts in UpdateUser's body (one locked read per
// write). It does not check that the write is built from that read; the
// TestUserRowNarrow_* / TestCTAReview_UserRowNarrow_* race tests prove that.
func TestUpdateUserWrites_AreBuiltFromALockedRead(t *testing.T) {
	var writes, lockedReads int
	for _, c := range columnScopedFuncCalls(t, "../users.go", "KeyorixCore", "UpdateUser") {
		if c.Recv != "tx" {
			continue
		}
		switch c.Name {
		case "UpdateUserIfActiveStateMatches":
			writes++
		case "LockUserForUpdate":
			lockedReads++
		}
	}
	if writes == 0 {
		t.Fatal("UpdateUser makes no tx.UpdateUserIfActiveStateMatches call: the guard's subject changed; update the guard")
	}
	if lockedReads < writes {
		t.Errorf("UpdateUser has %d conditional profile writes but only %d tx.LockUserForUpdate re-reads: a write built from the unlocked GetUser reverts a concurrent rename/email change (#2653/#2654)", writes, lockedReads)
	}
}
