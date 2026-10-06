package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaleAccounts_PassesCutoffAndDefaultsState(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	want := c.now().Add(-7 * 24 * time.Hour)

	// Empty state defaults to pending_first_login.
	store.On("ListUsersInStateBefore", ctx, AccountPendingFirstLogin, want).
		Return([]*models.User{{ID: 1, AccountState: AccountPendingFirstLogin}}, nil)

	out, err := c.StaleAccounts(ctx, "", 7*24*time.Hour)
	require.NoError(t, err)
	assert.Len(t, out, 1)
	store.AssertCalled(t, "ListUsersInStateBefore", ctx, AccountPendingFirstLogin, want)
}

// The two tests that used to live here — TestProjectMembershipCounts_Delegates and
// TestListUserProjectMemberships_Delegates — asserted that core delegated straight
// to the ADR-022 journal (CountProjectMembershipsByUsers /
// ListUserProjectMemberships). That delegation WAS the #2781 bug: the journal is
// empty on any install whose project members were added through
// POST /projects/{id}/members, so both figures read zero for every user while the
// grants behind them were real. They are not adjusted to match the new behaviour —
// their premise ("the journal is the membership answer") is the thing that changed.
// The replacements, stating the new premise, are
// TestProjectMembershipCounts_CountsGrantsNotJournalRows and
// TestListProjectMembershipsForUser_* in
// project_membership_definition_test.go, and ListUserProjectMemberships no longer
// exists at all (see project_membership_definition_guard_test.go's
// TestProjectMembership_OneDefinition_NoCoreWrapperForJournalPerUserRead).
