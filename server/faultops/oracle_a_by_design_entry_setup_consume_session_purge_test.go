// One file per row family; never append to a shared list. See registry_entries_test.go.
package faultops

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// AUDIT-DISCLOSURE-NOV-1 item 3 (R1.16): completePasswordSetup now deletes the
// account's existing sessions inside its one transaction (listed first in a
// savepoint, setup_consume.go). A fault there refuses the consume exactly like the
// other writes of that transaction (oracle_a_by_design_entry_setup_consume_test.go):
// nothing committed, the dead-link 400, the slot kept, setup_token.consume_error.
// Found by TestOpFaultSweep over REST POST /auth/setup/consume: the purge itself
// (every kind), a panic in the listing (its error is retried and swallowed), and a
// panic in the listing's savepoint (WithTransaction call 2; call 1 is the consume
// transaction, already covered).
var setupConsumeSessionPurgeTuples = []struct {
	method string
	nth    int
	kinds  []faultstorage.FaultKind
}{
	{"DeleteSessionsForUserExcept", 1, allThreeKinds},
	{"ListSessionTokenHashesForUser", 1, panicOnly},
	{"WithTransaction", 2, panicOnly},
}

func init() {
	const op = "REST POST /auth/setup/consume"
	for _, tu := range setupConsumeSessionPurgeTuples {
		for _, kind := range tu.kinds {
			name := fmt.Sprintf("post_auth_setup_consume_session_purge_%s_%d_%s", strings.ToLower(tu.method), tu.nth,
				strings.ReplaceAll(kind.String(), "-", "_"))
			registerOracleAByDesign(name, oracleAByDesignError{
				op: op, method: tu.method, kind: kind, nth: tu.nth,
				tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
				wrongCredentialResponse: setupConsumeDeadLinkResponse,
				designComment:           setupConsumeDesign + "; since R1.16 the same transaction deletes the account's existing sessions",
				provingTest:             setupConsumeProvingTest + "; internal/core/TestCompleteSetup_SessionPurgeFails_ResetRefusedOldSessionCannotSurvive",
				why:                     setupConsumeWhy,
			})
		}
	}
}
