// One file per op's row family (PARTIAL-COMMIT-TAILS-NOV-3 item 2): every row
// below records the SAME decision as the account_setup rows
// (oracle_a_by_design_entry_setup_consume_test.go), for the invitation_accept
// variant of the route. New files only; never a shared list. See
// registry_entries_test.go.
package faultops

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const (
	setupInvitationDesign = "internal/core/setup_consume.go completeInvitationAccept: the invitation read, the " +
		"existing-account guard, the username derivation and the grant-scope check run before the account is " +
		"created, and the create is one transaction (createUser); a failure there is ErrSetupPostVerdict or a " +
		"storage error, before any write. server/http/handlers/auth.go ConsumeSetup answers it with the dead-link " +
		"400, keeps the per-IP slot and audits setup_token.consume_error"
	setupInvitationWhy = "The token was valid, a storage fault refused the accept before the account existed, and " +
		"nothing was written: the token is still active, the invitation pending, no account, grant or session. " +
		"What remains is exactly what a dead link costs: the same 400, the LoginAttempt slot kept, a failure " +
		"audit. Answering or charging it differently would tell the caller the token was valid."
	setupInvitationProvingTest = "internal/core/TestCompleteInvitationAccept_ReadFaultIsTypedPostVerdict; " +
		"server/http/handlers/TestConsumeSetup_InvitationReadFault_DeadLinkAnswer_AuditedAsError"
)

// setupInvitationPreAccountTuples are the (method, nth, kinds) whose fault the
// exhaustive sweep (TestOpFaultSweep, every method x nth 1-5 x kind) found
// refusing the accept before the account was created: the diff was LoginAttempt
// plus the audit row and nothing else. GetUserByEmail#2 and GetUserByUsername#2
// are createUser's own uniqueness pre-checks; GetRoleByName#1 is
// requireInvitationGrantScopesValid; WithTransaction#1 / CreateUser#1 is the
// create transaction.
var setupInvitationPreAccountTuples = []struct {
	method string
	nth    int
	kinds  []faultstorage.FaultKind
}{
	{"CreateUser", 1, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}},
	{"GetProjectInvitation", 1, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}},
	{"GetRoleByName", 1, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}},
	{"GetUserByEmail", 1, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}},
	{"GetUserByEmail", 2, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}},
	{"GetUserByUsername", 1, []faultstorage.FaultKind{faultstorage.KindPanic}},
	{"GetUserByUsername", 2, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}},
	{"WithTransaction", 1, []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic}},
}

func init() {
	for _, tu := range setupInvitationPreAccountTuples {
		for _, kind := range tu.kinds {
			name := fmt.Sprintf("post_auth_setup_consume_invitation_%s_%d_%s", strings.ToLower(tu.method), tu.nth,
				strings.ReplaceAll(kind.String(), "-", "_"))
			registerOracleAByDesign(name, oracleAByDesignError{
				op: setupInvitationOpKey, method: tu.method, kind: kind, nth: tu.nth,
				tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
				wrongCredentialResponse: setupConsumeDeadLinkResponse,
				designComment:           setupInvitationDesign,
				provingTest:             setupInvitationProvingTest,
				why:                     setupInvitationWhy,
			})
		}
	}
}
