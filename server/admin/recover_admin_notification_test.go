package admin

import (
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// The admin notification says when --force-unsuspend lifted a block, and says
// nothing about it otherwise.
func TestRecoverAdminNotification_NamesLiftedState(t *testing.T) {
	summary := &recoverAdminSummary{userID: 7, username: "root-admin", operator: `"ops" (uid 0)`}

	plain := recoverAdminNotification(summary, "generation 1 of the recovery key")
	if strings.Contains(plain, "--force-unsuspend") {
		t.Errorf("notification mentions --force-unsuspend for an account that was not blocked: %q", plain)
	}

	summary.liftedState = core.AccountSuspended
	forced := recoverAdminNotification(summary, "generation 1 of the recovery key")
	if !strings.Contains(forced, strconv.Quote(core.AccountSuspended)) || !strings.Contains(forced, "--force-unsuspend lifted that state") {
		t.Errorf("notification does not name the lifted state: %q", forced)
	}
	if !strings.Contains(forced, "investigate immediately") {
		t.Errorf("notification lost its warning: %q", forced)
	}
}
