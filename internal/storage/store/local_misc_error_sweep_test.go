// local_misc_error_sweep_test.go — DB-error branch sweep, following the
// newBrokenDB pattern (store_s35_test.go), for several small single-function
// files: local_memberships.go, local_machine_identities.go,
// local_machine_credentials.go, local_mfa.go, local_mfa_stepup_grant.go.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestTransitionProjectMembershipState_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.TransitionProjectMembershipState(context.Background(), &models.ProjectMembership{ID: 1}, "active")
	require.Error(t, err)
}

func TestGetMachineIdentity_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetMachineIdentity(context.Background(), 1)
	require.Error(t, err)
}

func TestGetMachineIdentityCredentialByID_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetMachineIdentityCredentialByID(context.Background(), 1)
	require.Error(t, err)
}

func TestAssignMachineRole_CreateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.MachineIdentityRole{})
	dropTableAfterQueries(t, ls.db, 1, "machine_identity_roles")

	err := ls.AssignMachineRole(context.Background(), 1, 2, storage.Scope{})
	require.Error(t, err)
}

func TestGetMachineRoleScopes_ScanFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetMachineRoleScopes(context.Background(), 1)
	require.Error(t, err)
}

func TestGetOIDCBindingByID_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetOIDCBindingByID(context.Background(), 1)
	require.Error(t, err)
}

func TestConsumeMFAChallenge_LoadFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.MFAChallenge{})
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.MFAChallenge{
		TokenHash: "tok-abc", ExpiresAt: time.Now().Add(time.Hour),
	}).Error)

	dropTableAfterUpdates(t, ls.db, 1, "mfa_challenges")

	_, err := ls.ConsumeMFAChallenge(ctx, "tok-abc", time.Now())
	require.Error(t, err)
}

func TestGetActiveMFAStepUpGrant_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetActiveMFAStepUpGrant(context.Background(), 1, time.Now())
	require.Error(t, err)
}

func TestGetConnectorProjectBinding_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetConnectorProjectBinding(context.Background(), "connector-1")
	require.Error(t, err)
}

func TestListConnectorProjectBindings_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListConnectorProjectBindings(context.Background())
	require.Error(t, err)
}

func TestGetBreakGlassActivation_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetBreakGlassActivation(context.Background(), 1)
	require.Error(t, err)
}

func TestReconcileExpiredBreakGlassActivation_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.ReconcileExpiredBreakGlassActivation(context.Background(), 1, 2)
	require.Error(t, err)
}
