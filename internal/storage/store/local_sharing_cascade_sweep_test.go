// local_sharing_cascade_sweep_test.go — partial-coverage sweep for
// local_sharing.go: the CreateShareRecord create-race recovery branches
// (#136), and DB-error paths reached via newBrokenDB, partial migration, or
// dropTableAfterQueries (shared helpers defined in
// local_secrets_cascade_sweep_test.go, same package).
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newSharingRaceStore(t *testing.T) (*LocalStorage, *models.Project, *models.Environment, *models.SecretNode, *models.User) {
	t.Helper()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.User{}, &models.Group{})
	// Mirrors ensureShareRecordUniqueIndex in production: without a real
	// unique index, two identical share_records rows insert cleanly on
	// SQLite and CreateShareRecord's race-recovery branch never triggers.
	require.NoError(t, ls.db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_share_records_active ON share_records(secret_id, recipient_id, is_group) WHERE deleted_at IS NULL").Error)
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "share-race-proj"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	owner := &models.User{Username: "owner", UsernameFolded: "owner", EmailFolded: "owner@example.com"}
	require.NoError(t, ls.db.Create(owner).Error)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: env.ID, Name: "race-secret", IsSecret: true, OwnerID: owner.ID,
	})
	require.NoError(t, err)
	recipient := &models.User{Username: "recipient", UsernameFolded: "recipient", EmailFolded: "recipient@example.com"}
	require.NoError(t, ls.db.Create(recipient).Error)
	return ls, p, env, secret, recipient
}

func TestCreateShareRecord_RaceRecoverySucceeds(t *testing.T) {
	t.Parallel()
	ls, _, _, secret, recipient := newSharingRaceStore(t)
	ctx := context.Background()

	calls := 0
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("share-race-insert", func(_ *gorm.DB) {
		calls++
		if calls == 3 {
			// Simulate a concurrent winner: insert the competing row right
			// after CreateShareRecord's own existence check just missed it.
			ls.db.Create(&models.ShareRecord{
				SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false,
				OwnerID: secret.OwnerID, Permission: "read",
			})
		}
	}))

	got, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false,
		OwnerID: secret.OwnerID, Permission: "write",
	})
	require.NoError(t, err)
	assert.Equal(t, "write", got.Permission)
}

func TestCreateShareRecord_RaceRecoverySaveFails(t *testing.T) {
	t.Parallel()
	ls, _, _, secret, recipient := newSharingRaceStore(t)
	ctx := context.Background()

	calls := 0
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("share-race-insert-then-drop", func(_ *gorm.DB) {
		calls++
		switch calls {
		case 3:
			ls.db.Create(&models.ShareRecord{
				SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false,
				OwnerID: secret.OwnerID, Permission: "read",
			})
		case 4:
			ls.db.Exec("DROP TABLE share_records")
		}
	}))

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false,
		OwnerID: secret.OwnerID, Permission: "write",
	})
	require.Error(t, err)
}

func TestCreateShareRecord_CreateFailsGenericError(t *testing.T) {
	t.Parallel()
	ls, _, _, secret, recipient := newSharingRaceStore(t)
	ctx := context.Background()

	// Drop share_records right after the initial (not-found) existence check
	// (the 3rd query-family call), so Create fails with "no such table" -- not
	// a unique-constraint error, exercising the outer generic-error fallback.
	dropTableAfterQueries(t, ls.db, 3, "share_records")

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false,
		OwnerID: secret.OwnerID, Permission: "write",
	})
	require.Error(t, err)
}

func TestCreateShareRecord_ExistingCheckGenericError(t *testing.T) {
	t.Parallel()
	// share_records intentionally absent: GetSecret and the recipient-existence
	// check succeed, but the existing-share lookup fails with a non-not-found error.
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.User{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "no-share-table"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	owner := &models.User{Username: "o2", UsernameFolded: "o2", EmailFolded: "o2@example.com"}
	require.NoError(t, ls.db.Create(owner).Error)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: env.ID, Name: "s2", IsSecret: true, OwnerID: owner.ID,
	})
	require.NoError(t, err)
	recipient := &models.User{Username: "r2", UsernameFolded: "r2", EmailFolded: "r2@example.com"}
	require.NoError(t, ls.db.Create(recipient).Error)

	_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false, OwnerID: owner.ID, Permission: "write",
	})
	require.Error(t, err)
}

func TestCreateShareRecord_UpdateExistingSaveFails(t *testing.T) {
	t.Parallel()
	ls, _, _, secret, recipient := newSharingRaceStore(t)
	ctx := context.Background()

	require.NoError(t, ls.db.Create(&models.ShareRecord{
		SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false, OwnerID: secret.OwnerID, Permission: "read",
	}).Error)

	// 3 query-family calls precede the Save: GetSecret, recipient Count, and
	// the existing-share lookup (found this time). Drop share_records right after.
	dropTableAfterQueries(t, ls.db, 3, "share_records")

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: recipient.ID, IsGroup: false, OwnerID: secret.OwnerID, Permission: "write",
	})
	require.Error(t, err)
}

func TestCreateShareRecord_GroupCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.User{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "grp-count-fail"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	owner := &models.User{Username: "o3", UsernameFolded: "o3", EmailFolded: "o3@example.com"}
	require.NoError(t, ls.db.Create(owner).Error)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: env.ID, Name: "s3", IsSecret: true, OwnerID: owner.ID,
	})
	require.NoError(t, err)

	// Group table intentionally absent.
	_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: 99, IsGroup: true, OwnerID: owner.ID, Permission: "read",
	})
	require.Error(t, err)
}

func TestCreateShareRecord_UserCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "usr-count-fail"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	secret, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: env.ID, Name: "s4", IsSecret: true, OwnerID: 1,
	})
	require.NoError(t, err)

	// User table intentionally absent.
	_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, RecipientID: 99, IsGroup: false, OwnerID: 1, Permission: "read",
	})
	require.Error(t, err)
}

func TestGetShareRecord_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetShareRecord(context.Background(), 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "ErrorShareNotFound")
}

func TestUpdateShareRecord_SaveFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.ShareRecord{})
	ctx := context.Background()
	share := &models.ShareRecord{SecretID: 1, RecipientID: 2, OwnerID: 3, Permission: "read"}
	require.NoError(t, ls.db.Create(share).Error)

	dropTableAfterQueries(t, ls.db, 1, "share_records")

	_, err := ls.UpdateShareRecord(ctx, &models.ShareRecord{ID: share.ID, Permission: "write"})
	require.Error(t, err)
}

func TestDeleteShareRecord_DeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.ShareRecord{})
	ctx := context.Background()
	share := &models.ShareRecord{SecretID: 1, RecipientID: 2, OwnerID: 3, Permission: "read"}
	require.NoError(t, ls.db.Create(share).Error)

	dropTableAfterQueries(t, ls.db, 1, "share_records")

	err := ls.DeleteShareRecord(ctx, share.ID)
	require.Error(t, err)
}

func TestListSharedSecrets_DirectQueryBrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSharedSecrets(context.Background(), 1)
	require.Error(t, err)
}

func TestListSharedSecrets_GroupQueryFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.ShareRecord{}, &models.User{})
	// groups/user_groups tables intentionally absent.
	_, err := ls.ListSharedSecrets(context.Background(), 1)
	require.Error(t, err)
}

func TestCheckSharePermission_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.CheckSharePermission(context.Background(), 1, 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "ErrorSecretNotFound")
}

func TestCheckSharePermission_OwnerActiveCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	ctx := context.Background()
	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "owner-count-fail", IsSecret: true, OwnerID: 5}
	require.NoError(t, ls.db.Create(secret).Error)

	// users table intentionally absent.
	_, err := ls.CheckSharePermission(ctx, secret.ID, 5)
	require.Error(t, err)
}

func TestCheckSharePermission_DirectShareQueryFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	ctx := context.Background()
	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "direct-fail", IsSecret: true, OwnerID: 0}
	require.NoError(t, ls.db.Create(secret).Error)

	// share_records/users tables intentionally absent, userID != OwnerID so the
	// owner branch is skipped entirely.
	_, err := ls.CheckSharePermission(ctx, secret.ID, 7)
	require.Error(t, err)
}

func TestCheckSharePermission_GroupShareQueryFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.ShareRecord{}, &models.User{})
	ctx := context.Background()
	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "group-fail", IsSecret: true, OwnerID: 0}
	require.NoError(t, ls.db.Create(secret).Error)

	// groups/user_groups tables intentionally absent; direct-share query
	// succeeds (finds nothing) since share_records/users exist.
	_, err := ls.CheckSharePermission(ctx, secret.ID, 9)
	require.Error(t, err)
}
