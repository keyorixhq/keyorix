// group_errorpath_test.go — deterministic coverage for the wrapped
// service-error branches (`fmt.Errorf("failed to ... group: %w", err)`) that
// the existing test files leave to chance ("may or may not error"). Each test
// here drives a service call that is *guaranteed* to fail against a fresh,
// empty local DB (operating on a group ID that cannot exist yet), so the
// error branch is exercised deterministically rather than incidentally.
package group

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunGet_CLI_NotFound_Deterministic drives runGet against a fresh local DB
// with a group ID that is guaranteed not to exist, covering get.go's
// "failed to get group" wrapped-error branch deterministically.
func TestRunGet_CLI_NotFound_Deterministic(t *testing.T) {
	setupLocalDB(t)

	orig := getGroupID
	defer func() { getGroupID = orig }()
	getGroupID = 99999

	err := runGet(nil, nil)
	require.Error(t, err, "getting a nonexistent group must fail, not silently succeed")
	assert.Contains(t, err.Error(), "failed to get group")
}

// TestRunUpdate_CLI_NotFound_Deterministic drives runUpdate against a fresh
// local DB with a group ID that is guaranteed not to exist, covering
// update.go's "failed to update group" wrapped-error branch deterministically.
func TestRunUpdate_CLI_NotFound_Deterministic(t *testing.T) {
	setupLocalDB(t)

	origID, origName := updateGroupID, updateGroupName
	defer func() { updateGroupID = origID; updateGroupName = origName }()
	updateGroupID = 99999
	updateGroupName = "does-not-matter"

	err := runUpdate(nil, nil)
	require.Error(t, err, "updating a nonexistent group must fail, not silently succeed")
	assert.Contains(t, err.Error(), "failed to update group")
}

// TestRunDelete_CLI_Force_NotFound_Deterministic drives runDelete with --force
// (skipping the confirmation prompt) against a fresh local DB with a group ID
// that is guaranteed not to exist, covering delete.go's "failed to delete
// group" wrapped-error branch deterministically.
func TestRunDelete_CLI_Force_NotFound_Deterministic(t *testing.T) {
	setupLocalDB(t)

	origID, origForce := deleteGroupID, deleteForce
	defer func() { deleteGroupID = origID; deleteForce = origForce }()
	deleteGroupID = 99999
	deleteForce = true

	err := runDelete(nil, nil)
	require.Error(t, err, "force-deleting a nonexistent group must fail, not silently succeed")
	assert.Contains(t, err.Error(), "failed to delete group")
}

// TestRunCreate_CLI_DuplicateName_Deterministic drives runCreate twice with the
// same name against a fresh local DB. Group names are enforced unique by a
// partial unique index (name WHERE deleted_at IS NULL) applied during the real
// migration path that common.InitializeCoreService uses (see
// internal/storage/models.Group's doc comment), so the second create is
// guaranteed to fail — covering create.go's "failed to create group" wrapped-
// error branch deterministically.
func TestRunCreate_CLI_DuplicateName_Deterministic(t *testing.T) {
	setupLocalDB(t)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "duplicate-name-target"
	createDescription = ""

	require.NoError(t, runCreate(nil, nil), "first create with a fresh name must succeed")

	err := runCreate(nil, nil)
	require.Error(t, err, "creating a second group with the same name must fail, not silently succeed")
	assert.Contains(t, err.Error(), "failed to create group")
}

// TestRunDelete_CLI_NoForce_ConfirmedYes_NotFound_Deterministic covers the
// branch where the (non-force) confirmation prompt is answered "yes" for a
// group that does not exist: the GetGroup label lookup fails (fallback label
// used — already covered by TestRunDelete_CancelledByPrompt's "no" case), the
// prompt is confirmed, and the subsequent service.DeleteGroup call then
// surfaces the "failed to delete group" error. This exercises the "yes at the
// prompt but service call still fails" path, which is distinct from both the
// force-mode error test above and the "no" cancellation test.
func TestRunDelete_CLI_NoForce_ConfirmedYes_NotFound_Deterministic(t *testing.T) {
	setupLocalDB(t)

	origID, origForce := deleteGroupID, deleteForce
	defer func() { deleteGroupID = origID; deleteForce = origForce }()
	deleteGroupID = 88888
	deleteForce = false

	var err error
	withStdin(t, "yes\n", func() {
		err = runDelete(nil, nil)
	})
	require.Error(t, err, "confirming deletion of a nonexistent group must still surface the service error")
	assert.Contains(t, err.Error(), "failed to delete group")
}

// TestRunList_CLI_Deterministic_MultipleGroups exercises the list.go for-loop
// body over more than one row via the real CLI RunE path, and asserts on the
// count returned by the underlying service to confirm runList is reading the
// same store it just wrote to (not merely "no panic").
func TestRunList_CLI_Deterministic_MultipleGroups(t *testing.T) {
	setupLocalDB(t)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()

	createName = "list-det-a"
	createDescription = "first"
	require.NoError(t, runCreate(nil, nil))
	createName = "list-det-b"
	createDescription = "second"
	require.NoError(t, runCreate(nil, nil))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	groups, err := svc.ListGroups(context.Background())
	require.NoError(t, err)
	require.Len(t, groups, 2, "both created groups must be visible to the same store runList reads from")

	assert.NoError(t, runList(nil, nil))
}
