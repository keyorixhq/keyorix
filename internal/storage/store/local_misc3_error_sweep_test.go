// local_misc3_error_sweep_test.go — DB-error and small-logic-branch sweep for
// local_system_metadata.go, local_stats.go, local_sso.go, local_sod.go,
// local_secret_acl.go, and local_secret_schedule.go.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestGetSystemMetadata_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, _, err := ls.GetSystemMetadata(context.Background(), "some-key")
	require.Error(t, err)
}

func TestGetStats_UsersCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	_, err := ls.GetStats(context.Background())
	require.Error(t, err)
}

func TestGetStats_RolesCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.User{})
	_, err := ls.GetStats(context.Background())
	require.Error(t, err)
}

func TestGetStats_SessionsCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.User{}, &models.Role{})
	_, err := ls.GetStats(context.Background())
	require.Error(t, err)
}

func TestGetPreviousDeploymentStatsSnapshot_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetPreviousDeploymentStatsSnapshot(context.Background())
	require.Error(t, err)
}

func TestConsumeSSOLoginState_DeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SSOLoginState{})
	require.NoError(t, ls.db.Create(&models.SSOLoginState{
		State: "state-1", Nonce: "nonce-1", Provider: "oidc", ExpiresAt: time.Now().Add(time.Hour),
	}).Error)

	dropTableAfterQueries(t, ls.db, 1, "sso_login_states")

	_, err := ls.ConsumeSSOLoginState(context.Background(), "state-1")
	require.Error(t, err)
}

func TestConsumeSSOLoginState_LostRace(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SSOLoginState{})
	require.NoError(t, ls.db.Create(&models.SSOLoginState{
		State: "state-2", Nonce: "nonce-2", Provider: "oidc", ExpiresAt: time.Now().Add(time.Hour),
	}).Error)

	// Simulate a concurrent consumer winning the DELETE race between this
	// call's own First() and its own Delete().
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("sso-race-delete", func(_ *gorm.DB) {
		ls.db.Exec("DELETE FROM sso_login_states WHERE state = ?", "state-2")
	}))

	_, err := ls.ConsumeSSOLoginState(context.Background(), "state-2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetSoDPolicy_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetSoDPolicy(context.Background(), 1)
	require.Error(t, err)
}

func TestCreateOrUpdateSecretACL_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.CreateOrUpdateSecretACL(context.Background(), &models.SecretACL{SecretID: 1, UserID: 2})
	require.Error(t, err)
}

func TestListSecretACLs_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSecretACLs(context.Background(), 1)
	require.Error(t, err)
}

func TestListSecretACLsByUser_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSecretACLsByUser(context.Background(), 1)
	require.Error(t, err)
}

func TestDeleteSecretACL_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.DeleteSecretACL(context.Background(), 1)
	require.Error(t, err)
}

func TestDeleteSecretACLsByUserAndProject_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.DeleteSecretACLsByUserAndProject(context.Background(), 1, 2)
	require.Error(t, err)
}

func TestSetSecretAccessSchedule_UpdateExistingSaveFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretAccessSchedule{})
	require.NoError(t, ls.db.Create(&models.SecretAccessSchedule{
		SecretNodeID: 1, AllowedDays: "1,2,3", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}).Error)

	dropTableAfterQueries(t, ls.db, 1, "secret_access_schedules")

	err := ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
		SecretNodeID: 1, AllowedDays: "1,2,3,4,5", StartHour: 8, EndHour: 18, Timezone: "UTC",
	})
	require.Error(t, err)
}
