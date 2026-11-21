// One file per row family (INVITE-ACCEPT-NOV-1 item 4, #4410): the invitation_accept
// variant of POST /auth/setup/consume when spending the link itself fails after the
// account was created. New files only; never a shared list. See registry_entries_test.go.
package faultops

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const (
	setupInvitationSpendDesign = "internal/core/setup_consume.go completeInvitationAccept: a failed (or panicking, " +
		"runInvitationAcceptStep) consumeInspectedToken runs abandonInvitationAccept, which removes the account it " +
		"had just created together with its baseline role and password history (removeInvitationAcceptAccount, one " +
		"transaction); nothing was granted yet and the link was not spent. server/http/handlers/auth.go ConsumeSetup " +
		"answers it with the dead-link 400 and keeps the per-IP slot"
	setupInvitationSpendWhy = "Spending the link failed, so the accept is undone before anything was granted: the " +
		"account is removed with everything CreateUser gave it, the link is still live and the invitation pending, so " +
		"the same link works again. What remains is what a dead link costs: the same 400, the LoginAttempt slot kept " +
		"and a failure audit, so the answer never tells the caller the token was valid."
	setupInvitationSpendProvingTest = "internal/core/TestCompleteInvitationAccept_FailureAtEachStep_UndoesAndSaysWhatHappened; " +
		"internal/core/TestCompleteInvitationAccept_PanicAtEachStep_UndoesTheAccept; " +
		"internal/core/TestCompleteInvitationAccept_AbandonRemovesBaselineRoleAndPasswordHistory"
)

func init() {
	// effect-then-error spends the link and is the consume-first entry's
	// (consume_first_oracle_test.go), not a row here.
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		name := fmt.Sprintf("post_auth_setup_consume_invitation_marksetuptokenconsumed_1_%s", strings.ReplaceAll(kind.String(), "-", "_"))
		registerOracleAByDesign(name, oracleAByDesignError{
			op: setupInvitationOpKey, method: "MarkSetupTokenConsumed", kind: kind, nth: 1,
			tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
			wrongCredentialResponse: setupConsumeDeadLinkResponse,
			designComment:           setupInvitationSpendDesign,
			provingTest:             setupInvitationSpendProvingTest,
			why:                     setupInvitationSpendWhy,
		})
	}
}
