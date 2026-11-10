package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

type fakeLegacyRoleGrantLister struct {
	grants      []core.LegacyRoleProjectGrant
	invitations []core.InvitationOutsideScope
	grantsErr   error
	invErr      error
}

func (f fakeLegacyRoleGrantLister) ListLegacyRoleProjectGrants(context.Context) ([]core.LegacyRoleProjectGrant, error) {
	return f.grants, f.grantsErr
}

func (f fakeLegacyRoleGrantLister) ListPendingInvitationsOutsideAssignableScope(context.Context) ([]core.InvitationOutsideScope, error) {
	return f.invitations, f.invErr
}

// TestCollectLegacyRoleGrantsPosture: the grants are warnings, because they keep
// working, so they never change the command's exit code; an invitation is listed
// only when it is a legacy role at a project.
func TestCollectLegacyRoleGrantsPosture(t *testing.T) {
	report := &postureReport{}
	collectLegacyRoleGrantsPosture(context.Background(), &config.Config{}, fakeLegacyRoleGrantLister{
		grants: []core.LegacyRoleProjectGrant{{PrincipalType: "machine", PrincipalID: 4, Principal: "ci-reader",
			RoleName: "viewer", Replacement: "project_viewer", ProjectID: 2, Project: "payments"}},
		invitations: []core.InvitationOutsideScope{
			{InvitationID: 7, Email: "a@example.com", RoleName: "viewer", ProjectID: 2},
			{InvitationID: 8, Email: "b@example.com", RoleName: "project_viewer"},
		},
	}, report)

	assert.Empty(t, report.deviations, "existing grants must not fail the check")
	require.Len(t, report.warnings, 3, "%v", report.warnings)
	assert.Contains(t, report.warnings[0], "1 existing per-project grant(s) of a legacy role")
	assert.Contains(t, report.warnings[1], "machine ci-reader holds viewer on project payments")
	assert.Contains(t, report.warnings[1], "keyorix machine grant-role ci-reader --project payments --role project_viewer")
	assert.Contains(t, report.warnings[2], "invitation 7 (a@example.com) grants viewer at project_id=2")
	assert.Contains(t, report.warnings[2], "invite with project_viewer instead")
}

// TestCollectLegacyRoleGrantsPosture_LegacyEmergencyRole: a legacy emergency role
// fails every activation, so it is a deviation that names the fix; disabled
// break-glass, or a project role, is not reported.
func TestCollectLegacyRoleGrantsPosture_LegacyEmergencyRole(t *testing.T) {
	collect := func(enabled bool, role string) *postureReport {
		cfg := &config.Config{}
		cfg.BreakGlass.Enabled, cfg.BreakGlass.EmergencyRole = enabled, role
		report := &postureReport{}
		collectLegacyRoleGrantsPosture(context.Background(), cfg, fakeLegacyRoleGrantLister{}, report)
		return report
	}
	r := collect(true, "editor")
	require.Len(t, r.deviations, 1)
	assert.Contains(t, r.deviations[0].detail, "break_glass.emergency_role editor")
	assert.Contains(t, r.deviations[0].detail, "project_developer")
	assert.Empty(t, collect(false, "editor").deviations, "break-glass off: nothing can be refused")
	assert.Empty(t, collect(true, "project_developer").deviations)
}

func TestCollectLegacyRoleGrantsPosture_NoGrantsNoWarning(t *testing.T) {
	report := &postureReport{}
	collectLegacyRoleGrantsPosture(context.Background(), &config.Config{}, fakeLegacyRoleGrantLister{}, report)
	assert.Empty(t, report.deviations)
	assert.Empty(t, report.warnings)
}

// TestCollectLegacyRoleGrantsPosture_ReadFailureIsNotClean: a check that could
// not read must say so, never report an empty list.
func TestCollectLegacyRoleGrantsPosture_ReadFailureIsNotClean(t *testing.T) {
	for name, lister := range map[string]fakeLegacyRoleGrantLister{
		"grants":      {grantsErr: errors.New("boom")},
		"invitations": {invErr: errors.New("boom")},
	} {
		t.Run(name, func(t *testing.T) {
			report := &postureReport{}
			collectLegacyRoleGrantsPosture(context.Background(), &config.Config{}, lister, report)
			require.Len(t, report.deviations, 1)
			assert.Equal(t, "legacy-role-grants", report.deviations[0].category)
			assert.Contains(t, report.deviations[0].detail, "NOT evaluated")
		})
	}
}
