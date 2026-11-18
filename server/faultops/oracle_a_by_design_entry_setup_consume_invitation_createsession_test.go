// One file per row family (INVITE-ACCEPT-NOV-1 item 2, #4409 shape 2): the
// invitation_accept variant of POST /auth/setup/consume, when the login session
// insert fails after the accept committed. New files only; never a shared list.
// See registry_entries_test.go.
package faultops

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const (
	setupInvitationSignInDesign = "internal/core/setup_consume.go completeInvitationAccept: mintLoginSession runs " +
		"only after the account, its grants and the accepted invitation committed, and its failure (error, or a " +
		"panic it recovers) returns ErrInvitationAcceptedSignInFailed with nothing undone; " +
		"server/http/handlers/auth.go ConsumeSetup answers it \"log in with your new password\", keeps the slot " +
		"(no session delivered) and audits setup_token.consume_error"
	setupInvitationSignInWhy = "Everything the accept is for committed: the account with the password just set, the " +
		"invitation's grant and the accepted invitation. Only the automatic sign-in failed, so undoing the accept " +
		"would throw away a valid account behind a link that is already spent. The invitee is told to log in, the " +
		"per-IP slot is kept because no session was delivered, and no session row exists."
	setupInvitationSignInProvingTest = "server/http/handlers/TestConsumeSetup_InvitationSignInFault_SaysLogInWithTheNewPassword; " +
		"internal/core/TestCompleteInvitationAccept_FailureAtEachStep_UndoesAndSaysWhatHappened"
)

func init() {
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		name := fmt.Sprintf("post_auth_setup_consume_invitation_createsession_1_%s", strings.ReplaceAll(kind.String(), "-", "_"))
		registerOracleAByDesign(name, oracleAByDesignError{
			op: setupInvitationOpKey, method: "CreateSession", kind: kind, nth: 1,
			tables: []string{"LoginAttempt", "PasswordHistory", "ProjectInvitation", "ProjectMembership", "SetupToken",
				"User", "UserRole"},
			outcomeLogs:   []string{"AuditEvent"},
			designComment: setupInvitationSignInDesign,
			provingTest:   setupInvitationSignInProvingTest,
			why:           setupInvitationSignInWhy,
		})
	}
}
