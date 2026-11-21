// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

// The invitation_accept variant of POST /auth/setup/consume creates the account
// through c.CreateUser, whose baseline system_viewer grant is best-effort
// (besteffort.Run "users.CreateUser.AssignBaselineRole", internal/core/users.go):
// a fault in its nested savepoint (WithTransaction#1 is the create transaction itself) leaves the invitee with FEWER roles than the
// reference run and the accept succeeds. The same decision as
// the AssignRole and GetRoleByName entries for POST /api/v1/users/
// (PARTIAL-COMMIT-TAILS-NOV-3 item 2). The tables check keeps later WithTransaction calls
// of this op, which are load-bearing grant steps with a wider diff, out of it.
func init() {
	registerOpScopedBestEffort("setup_consume_invitation_withtransaction", opScopedBestEffortTable{
		op: setupInvitationOpKey, method: "WithTransaction", tables: []string{"UserRole"}, minNthCall: 2,
		pinnedKinds: []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic},
	})
}
