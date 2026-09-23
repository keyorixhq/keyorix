// group_editor_escalation_falsification_test.go — falsification probe for a
// "Critical: AddGroupMemberProxy grants direct secrets read/write/delete via
// an editor-holding group" claim made in this PR's (#1979) initial severity
// pass, checked against origin/main directly (before this PR's fixes) and
// found FALSE.
//
// Hypothesis under test: a system.write-only caller (human or machine
// relay) can join (or add another user to) a group that already holds the
// editor role (secrets.read/write/delete, a real non-empty permission
// bundle) and come away with those permissions, because
// validateGroupJoinRoles's per-grant loop calling
// requireGranterHoldsRolePermissions was believed to be structurally
// vacuous for this case.
//
// Empirically FALSE, confirmed by running these exact requests against
// origin/main in an isolated worktree, before this branch's fixes:
// requireGranterHoldsRolePermissions (pre-fix) loops over the ROLE'S OWN
// bundled permissions (GetRolePermissions) and, for each one, requires the
// caller to already hold it (c.Authorize for a human, or an unconditional
// false for an untagged machine actor). editor's bundle is non-empty
// (secrets.read/write/delete/users.read) -- the per-permission loop runs
// and refuses a caller holding neither. Both the human-caller and the
// machine-relay probe below were refused pre-fix with the exact error
// "cannot grant this role: you do not hold permission \"secrets.read\"
// yourself" -- membership never created, no secrets access ever resolved.
// The ONLY pre-fix defect found was a status-code misclassification
// (500 STORAGE_ERROR instead of 403 FORBIDDEN — AddGroupMemberProxy's error
// handling had no branch for a legitimate permission denial, only
// not-found vs. generic-500), not a security bypass.
//
// The vacuity this PR's source-level fix (requireGranterHoldsRolePermissions's
// new roles.assign baseline) and the groups_proxy.go handler fix actually
// close only bites when the LOOP BODY NEVER RUNS AT ALL: an empty role (no
// permissions) or, at validateGroupJoinRoles's own outer loop, a group with
// NO role grants whatsoever -- see
// TestG3Probe_AddGroupMemberProxy_SystemWriteOnly_AddsMemberToOrdinaryGroup
// (system_proxy_g3_gap_probes_test.go) for that narrower, real gap. This
// test asserts the escalation scenario stays refused post-fix too (defense
// in depth: even if the new unconditional roles.assign check were ever
// weakened or removed, validateGroupJoinRoles's own per-grant permission
// check independently refuses a caller who doesn't hold what a
// permission-bearing group's role bundles).
package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestGroupEditorEscalationFalsification_HumanCaller_Refused(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()

	token := createSystemWriteOnlyToken(t, c)
	caller, err := c.GetUserByEmail(ctx, "sys_write_only@example.com")
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID

	editorRole, err := c.Storage().GetRoleByName(ctx, "editor")
	require.NoError(t, err)
	perms, err := c.Storage().GetRolePermissions(ctx, editorRole.ID)
	require.NoError(t, err)
	require.NotEmptyf(t, perms, "sanity: editor must bundle real, non-empty permissions for this probe to mean anything")

	grp, err := c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "falsification-editor-group-human", Description: "holds editor at project scope"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, admin.ID, grp.ID, editorRole.ID, core.Scope{ProjectID: projectID}, false))

	before, err := c.Storage().ListGroupMembers(ctx, grp.ID)
	require.NoError(t, err)

	status, body := g3Do(t, serverURL, token, http.MethodPost,
		"/api/v1/system/groups/"+idStr(grp.ID)+"/members",
		map[string]any{"user_id": caller.ID, "project_id": projectID})

	after, err := c.Storage().ListGroupMembers(ctx, grp.ID)
	require.NoError(t, err)

	canReadSecrets, aerr := c.AuthorizePrincipal(ctx, core.ActorTypeUser, caller.ID, "secrets.read", core.Scope{ProjectID: projectID})
	require.NoError(t, aerr)

	t.Logf("falsification probe: system.write-only HUMAN caller=%d joining group %d (holds editor) as itself; status=%d body=%s; members before=%d after=%d; caller now holds secrets.read=%v",
		caller.ID, grp.ID, status, body, len(before), len(after), canReadSecrets)

	assert.NotEqual(t, http.StatusOK, status)
	assert.Len(t, after, len(before), "membership must not have been created")
	assert.False(t, canReadSecrets, "the caller must not have gained secrets.read via this route")
}

func TestGroupEditorEscalationFalsification_MachineRelay_Refused(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()

	_ = createSystemWriteOnlyToken(t, c) // seeds the shared "ceiling_test_system_writer" role createSystemWriteOnlyNodeToken reuses
	nodeToken := createSystemWriteOnlyNodeToken(t, c)
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID

	target, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "falsification-machine-target", Email: "falsification-machine-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	editorRole, err := c.Storage().GetRoleByName(ctx, "editor")
	require.NoError(t, err)

	grp, err := c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "falsification-editor-group-machine", Description: "holds editor at project scope"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, admin.ID, grp.ID, editorRole.ID, core.Scope{ProjectID: projectID}, false))

	before, err := c.Storage().ListGroupMembers(ctx, grp.ID)
	require.NoError(t, err)

	status, body := g3Do(t, serverURL, nodeToken, http.MethodPost,
		"/api/v1/system/groups/"+idStr(grp.ID)+"/members",
		map[string]any{"user_id": target.ID, "project_id": projectID})

	after, err := c.Storage().ListGroupMembers(ctx, grp.ID)
	require.NoError(t, err)

	canReadSecrets, aerr := c.AuthorizePrincipal(ctx, core.ActorTypeUser, target.ID, "secrets.read", core.Scope{ProjectID: projectID})
	require.NoError(t, aerr)

	t.Logf("falsification probe: system.write-only MACHINE relay adding user=%d to group %d (holds editor); status=%d body=%s; members before=%d after=%d; target now holds secrets.read=%v",
		target.ID, grp.ID, status, body, len(before), len(after), canReadSecrets)

	assert.NotEqual(t, http.StatusOK, status)
	assert.Len(t, after, len(before), "membership must not have been created")
	assert.False(t, canReadSecrets, "the target must not have gained secrets.read via this route")
}

func idStr(id uint) string {
	return fmt.Sprintf("%d", id)
}
