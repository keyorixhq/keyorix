// One file per op's row family (PARTIAL-COMMIT-TAILS-NOV-3 item 2): the
// invitation_accept variant of POST /auth/setup/consume (ops_auth_setup_consume_invitation_test.go),
// swept exhaustively (TestOpFaultSweep, every method x nth 1-5 x kind). Every row
// is one (method, nth, kind, oracle) tuple. An oracle (a) row carries the exact
// tables its diff showed, so a different divergence on the same tuple still fails;
// oracle (d) reports no table list (report("d", nil, ...)), so its rows are pinned
// on the tuple alone. New files only; never
// a shared list. See registry_entries_test.go.
package faultops

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

type setupInvitationTolerance struct {
	method string
	nth    int
	kind   faultstorage.FaultKind
	oracle string
	tables []string
}

// #4409 (a defect; remove these rows when it is fixed): a panic in a step after
// completeInvitationAccept created the account is answered with the dead-link 400
// but abandonInvitationAccept never runs, so the account stays live (User) with a
// spent or unusable link; CreateSession#1 (error and panic) answers the dead link
// for an accept that committed; UpdateProjectInvitation#1 effect-then-error leaves
// the invitation accepted with no account (ProjectInvitation).
var setupInvitationOrphanAccountTuples = []setupInvitationTolerance{
	{"AssignRole", 2, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"CreateProjectMembership", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"CreateSession", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectInvitation", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"CreateSession", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectInvitation", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"GetActiveProjectMembership", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"GetProject", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"GetProjectMembership", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"GetRole", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"GetRoleByName", 3, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"GetRoleByName", 4, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"GetRolePermissions", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"GetRolePermissions", 2, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"GetRolePermissions", 3, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"ListSoDPolicies", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"ListSoDPolicies", 2, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"LockNamedKeyInTx", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"LockUserForUpdate", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"MarkSetupTokenConsumed", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "User", "UserRole"}},
	{"ResolveUserPermissionAt", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"ResolveUserPermissionAt", 2, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"ResolveUserPermissionAt", 3, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"ResolveUserPermissionAt", 4, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"ResolveUserPermissionAt", 5, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"UpdateProjectInvitation", 1, faultstorage.KindEffectThenError, "d", nil},
	{"UpdateProjectInvitation", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"WithNamedLock", 1, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "User", "UserRole"}},
	{"WithNamedLock", 2, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
	{"WithTransaction", 3, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "User", "UserRole"}},
}

// #4410 (a decision; remove these rows when it is made): an error after the account
// was created runs abandonInvitationAccept as designed (account soft-deleted,
// grants reverted, invitation pending for a resend, the dead-link 400), but the
// spent link, the revoked membership row and the baseline role and password
// history on the removed account stay, which oracles (a)/(d) flag. Whether that is
// by design (a saga instrument for oracleAByDesignErrors) or residue to remove is
// the open question.
var setupInvitationCompensatedTuples = []setupInvitationTolerance{
	{"AssignRole", 2, faultstorage.KindEffectThenError, "d", nil},
	{"AssignRole", 2, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"CreateProjectMembership", 1, faultstorage.KindEffectThenError, "d", nil},
	{"CreateProjectMembership", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"GetProject", 1, faultstorage.KindEffectThenError, "d", nil},
	{"GetProject", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"GetProjectMembership", 1, faultstorage.KindEffectThenError, "d", nil},
	{"GetProjectMembership", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"GetRole", 1, faultstorage.KindEffectThenError, "d", nil},
	{"GetRole", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"GetRoleByName", 3, faultstorage.KindEffectThenError, "d", nil},
	{"GetRoleByName", 3, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"GetRoleByName", 4, faultstorage.KindEffectThenError, "d", nil},
	{"GetRoleByName", 4, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"GetRolePermissions", 1, faultstorage.KindEffectThenError, "d", nil},
	{"GetRolePermissions", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"GetRolePermissions", 2, faultstorage.KindEffectThenError, "d", nil},
	{"GetRolePermissions", 2, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"GetRolePermissions", 3, faultstorage.KindEffectThenError, "d", nil},
	{"GetRolePermissions", 3, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"ListSoDPolicies", 1, faultstorage.KindEffectThenError, "d", nil},
	{"ListSoDPolicies", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"ListSoDPolicies", 2, faultstorage.KindEffectThenError, "d", nil},
	{"ListSoDPolicies", 2, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"LockNamedKeyInTx", 1, faultstorage.KindEffectThenError, "d", nil},
	{"LockNamedKeyInTx", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"LockUserForUpdate", 1, faultstorage.KindEffectThenError, "d", nil},
	{"LockUserForUpdate", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"LogAuditEvent", 4, faultstorage.KindEffectThenError, "d", nil},
	{"LogAuditEvent", 4, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"LogAuditEvent", 4, faultstorage.KindPanic, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"MarkSetupTokenConsumed", 1, faultstorage.KindEffectThenError, "d", nil},
	{"MarkSetupTokenConsumed", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "UserRole"}},
	{"ResolveUserPermissionAt", 1, faultstorage.KindEffectThenError, "d", nil},
	{"ResolveUserPermissionAt", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"ResolveUserPermissionAt", 2, faultstorage.KindEffectThenError, "d", nil},
	{"ResolveUserPermissionAt", 2, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"ResolveUserPermissionAt", 3, faultstorage.KindEffectThenError, "d", nil},
	{"ResolveUserPermissionAt", 3, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"ResolveUserPermissionAt", 4, faultstorage.KindEffectThenError, "d", nil},
	{"ResolveUserPermissionAt", 4, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"ResolveUserPermissionAt", 5, faultstorage.KindEffectThenError, "d", nil},
	{"ResolveUserPermissionAt", 5, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"UpdateProjectInvitation", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"WithNamedLock", 1, faultstorage.KindEffectThenError, "d", nil},
	{"WithNamedLock", 1, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "SetupToken", "UserRole"}},
	{"WithNamedLock", 2, faultstorage.KindEffectThenError, "d", nil},
	{"WithNamedLock", 2, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
	{"WithTransaction", 3, faultstorage.KindEffectThenError, "d", nil},
	{"WithTransaction", 3, faultstorage.KindError, "a", []string{"AuditEvent", "LoginAttempt", "PasswordHistory", "ProjectMembership", "SetupToken", "UserRole"}},
}

func init() {
	for issue, tuples := range map[string][]setupInvitationTolerance{
		"#4409": setupInvitationOrphanAccountTuples,
		"#4410": setupInvitationCompensatedTuples,
	} {
		for _, tu := range tuples {
			name := fmt.Sprintf("setup_consume_invitation_%s_%d_%s_%s", strings.ToLower(tu.method), tu.nth,
				strings.ReplaceAll(tu.kind.String(), "-", "_"), tu.oracle)
			registerKnownOpenTolerance(name, knownOpenTolerance{
				op: setupInvitationOpKey, method: tu.method, kind: tu.kind, nth: tu.nth, oracle: tu.oracle,
				tables: tu.tables, issue: issue, expires: "2027-02-17",
				findingDoc: "https://github.com/keyorixhq/keyorix/issues/" + strings.TrimPrefix(issue, "#"),
			})
		}
	}
}
