// dashboard_machine_test.go — G33 regression: GetDashboardStats must resolve the
// audit.read gate for a machine-identity caller the same way it does for an
// equivalent human user (via AuthorizePrincipal), not the user-only Authorize
// that silently under-privileged every machine caller (a machine's UserID is
// always 0, so the old Authorize(ctx, userID, ...) call could never see a
// machine's actual machine_identity_roles grant).
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// seedMachineWithRole creates a machine identity and assigns it roleName at the
// given scope — the machine-identity mirror of seedUserWithRole
// (auth_bootstrap_rbac_test.go).
func seedMachineWithRole(t *testing.T, st *store.LocalStorage, roleName string, scope storage.Scope) uint {
	t.Helper()
	ctx := context.Background()
	m, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{Name: "ci-bot", State: MachineActive})
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoErrorf(t, err, "role %s must be seeded", roleName)
	require.NoError(t, st.AssignMachineRole(ctx, m.ID, role.ID, scope))
	return m.ID
}

// G33 detection_idea: a machine identity holding a role that grants audit.read
// must see the SAME deployment-wide dashboard aggregates as an equivalent human
// user holding the identical role. Before this fix, GetDashboardStats called the
// user-only Authorize(ctx, userID, "audit.read", Scope{}) for this gate; a
// machine identity's userID is always 0, so this call resolved zero roles
// regardless of the machine's actual machine_identity_roles grant, and
// hasAuditRead was always false for a machine caller — silently under-
// privileging it relative to a human holding the identical role.
func TestGetDashboardStats_MachineIdentityWithAuditReadMatchesEquivalentUser(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	auditorID := seedUserWithRole(t, st, "human-auditor", "system_auditor", storage.Scope{})
	machineID := seedMachineWithRole(t, st, "system_auditor", storage.Scope{})

	humanCtx := WithActorType(ctx, ActorTypeUser)
	machineCtx := WithActorType(ctx, ActorTypeMachine)

	humanStats, err := c.GetDashboardStats(humanCtx, auditorID, "human-auditor", auditorID)
	require.NoError(t, err)
	require.False(t, humanStats.Degraded)
	require.Greater(t, humanStats.ActiveUsers, int64(0), "sanity: the deployment must have at least one active user for this comparison to be meaningful")

	// A machine-identity caller: UserID/username are the zero values a real HTTP
	// handler would pass (UserContext.PrincipalID's doc), machineID is the actual
	// RBAC principal.
	machineStats, err := c.GetDashboardStats(machineCtx, 0, "", machineID)
	require.NoError(t, err)

	// Deployment-wide aggregates are computed identically once audit.read is
	// honoured, regardless of caller identity — equality here proves the
	// machine's role grant was actually consulted, not silently dropped.
	require.Equal(t, humanStats.ActiveUsers, machineStats.ActiveUsers, "ActiveUsers must match: both callers hold audit.read via an identical role")
	require.Equal(t, humanStats.AuditEvents30d, machineStats.AuditEvents30d)
	require.Equal(t, humanStats.InactiveUsers, machineStats.InactiveUsers)
}

// Pins the counterfactual: a machine identity holding NO audit.read-granting role
// must still see the baseline (non-deployment-wide) view, so the pass above
// genuinely demonstrates the granted role being honoured — not every machine
// caller unconditionally getting the deployment-wide aggregates regardless of
// its actual roles.
func TestGetDashboardStats_MachineIdentityWithoutRoleSeesBaseline(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	m, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{Name: "no-role-bot", State: MachineActive})
	require.NoError(t, err)

	machineCtx := WithActorType(ctx, ActorTypeMachine)
	stats, err := c.GetDashboardStats(machineCtx, 0, "", m.ID)
	require.NoError(t, err)
	require.Zero(t, stats.ActiveUsers, "a machine identity holding no audit.read role must not see the deployment-wide aggregates")
	require.Zero(t, stats.AuditEvents30d)
}
