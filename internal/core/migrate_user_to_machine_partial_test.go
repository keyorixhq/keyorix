// migrate_user_to_machine_partial_test.go — the verifying test for
// MigrateUserToMachine's class-P row in docs/atomicity-exempt.tsv
// ("partial success REPORTED to the caller").
//
// Added by ORACLE-A-1 (2026-10-05) answering a coordinator question: why was
// MigrateUserToMachine absent from the ledger despite making two writes outside
// a transaction with a documented partial-success branch? Answer: the static
// guard could not see the second write. atomicityWriteVerbRe had no `Suspend`,
// so `c.SuspendUser(...)` was not counted, the function showed only ONE write
// (CreateMachineIdentity) and sat below the guard's 2-write threshold. The
// seeding sweep did not miss it; the detector was blind to it. That verb is now
// in the regex (see its own comment there for how the full missing-verb set was
// derived, and which write-shaped prefixes are confirmed read-only), which
// makes this function flagged, which is why it now needs a classified row.
//
// Class P requires a test proving BOTH halves of its contract, because a
// function that drops either is a class-A bug wearing a P label:
//  1. the error names the partial state (which identity, which user), and
//  2. the committed effect is still RETURNED, so the caller can see what landed.
//
// A function that returned a bare error with a nil identity would leave the
// operator knowing something failed but not what to clean up.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestMigrateUserToMachine_SuspendFailureReportsPartialState injects a
// SetAccountState failure, which makes SuspendUser fail AFTER
// CreateMachineIdentity has already committed — the exact interleaving the
// class-P row describes.
func TestMigrateUserToMachine_SuspendFailureReportsPartialState(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMachineCore(store)
	ctx := context.Background()

	store.On("GetUserByUsername", ctx, "ci-bot").
		Return(&models.User{ID: 7, Username: "ci-bot", Email: "ci-bot@example.com", AccountState: "active"}, nil)
	store.On("CreateMachineIdentity", ctx, mock.Anything).
		Return(&models.MachineIdentity{ID: 20, ProjectID: 3, Name: "ci-bot", IdentityType: MachineTypeService, State: MachineActive}, nil)

	// SuspendUser's own preamble: the admin-rank ceiling and the last-admin
	// guard both pass trivially (the migrated user holds no role scopes).
	store.On("GetUserRoleScopes", ctx, uint(7)).Return([]Scope{}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(7), Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(7), Scope{}).Return([]uint{}, nil)
	store.On("GetUser", ctx, uint(7)).
		Return(&models.User{ID: 7, Username: "ci-bot", AccountState: "active"}, nil)

	// setAccountState collects the token hashes it will evict BEFORE writing the
	// state, so these are reached even on the failing path. .Maybe() because
	// which of them run depends on where setAccountState gives up, and this test
	// is about the partial-state REPORT, not about eviction bookkeeping.
	store.On("ListSessionTokenHashesForUser", ctx, uint(7)).Return([]string{}, nil).Maybe()
	store.On("ListPersonalAccessTokensByUser", ctx, uint(7)).Return([]*models.PersonalAccessToken{}, nil).Maybe()
	store.On("RevokeAllPersonalAccessTokensForUser", ctx, uint(7)).Return([]string{}, nil).Maybe()
	store.On("DeleteSessionsForUserExcept", ctx, uint(7), uint(0)).Return(nil).Maybe()

	// THE INJECTED FAULT: the suspension's own state write fails, after the
	// machine identity has already been created and committed.
	store.On("SetAccountState", ctx, uint(7), AccountSuspended, mock.Anything).
		Return(errors.New("injected fault: SetAccountState"))

	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil).Maybe()

	m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 9, true)

	// Contract half 1: the error is reported, and it NAMES the partial state.
	require.Error(t, err, "a suspend failure after the identity committed must be reported, not swallowed")
	assert.Contains(t, err.Error(), "machine identity 20",
		"the error must name the identity that WAS created, or the operator cannot find it")
	assert.Contains(t, err.Error(), "source user 7",
		"the error must name the user that was NOT suspended, or the operator cannot finish the job")

	// Contract half 2: the committed effect is still returned. This is the half
	// a plain `return nil, err` would silently drop — the caller would know
	// something failed but not that a machine identity now exists.
	require.NotNil(t, m, "the created identity must still be returned so the caller can see what committed")
	assert.Equal(t, uint(20), m.ID)

	// And the identity really was created, not merely reported: the write
	// happened before the fault, which is what makes this a partial commit
	// rather than a clean failure.
	store.AssertCalled(t, "CreateMachineIdentity", ctx, mock.Anything)
	store.AssertCalled(t, "SetAccountState", ctx, uint(7), AccountSuspended, mock.Anything)
}
