package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestBulkRenameSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.UserRole{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	other, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	// CheckSecretPermission gates the owner path on IsProjectMember (RBAC-001); seed
	// user 1 so the owning actor passes the project-membership guard.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)

	mk := func(name string, projectID uint, isSecret bool) uint {
		s, e := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: env.ID, Type: "password", OwnerID: 1,
			IsSecret: isSecret, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, e)
		return s.ID
	}

	// A policy requiring UPPER_SNAKE so non-conforming names exist to remediate.
	require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{
		Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$", MaxLength: 30,
	}))

	bad := mk("db-password", p.ID, true)          // violator we will fix
	folder := mk("a folder", p.ID, false)         // folder node
	taken := mk("EXISTING_NAME", p.ID, true)      // occupies a target name (collision)
	foreign := mk("other-secret", other.ID, true) // belongs to another project
	_ = taken

	t.Run("zero project or actor is rejected", func(t *testing.T) {
		_, err := c.BulkRenameSecrets(ctx, 0, []SecretRename{{ID: bad, NewName: "X"}}, false, "alice", 1, "", "")
		require.Error(t, err)
		_, err = c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: bad, NewName: "X"}}, false, "alice", 0, "", "")
		require.Error(t, err)
	})

	t.Run("empty renames is rejected", func(t *testing.T) {
		_, err := c.BulkRenameSecrets(ctx, p.ID, nil, false, "alice", 1, "", "")
		require.Error(t, err)
	})

	t.Run("a non-owner is skipped (per-secret write ACL)", func(t *testing.T) {
		mine := mk("non-conf-x", p.ID, true) // owned by user 1
		// User 2 holds no ownership/share on it — even with project secrets.write it must
		// not be renamable via the bulk op (parity with the single-secret PUT gate).
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: mine, NewName: "MINE_X"}}, false, "intruder", 2, "", "")
		require.NoError(t, err)
		assert.Equal(t, 0, rep.Renamed)
		require.Len(t, rep.Outcomes, 1)
		assert.Equal(t, renameStatusSkipped, rep.Outcomes[0].Status)
		assert.Contains(t, rep.Outcomes[0].Reason, "not authorized")
	})

	t.Run("dry run validates but changes nothing", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: bad, NewName: "DB_PASSWORD"}}, true, "alice", 1, "", "")
		require.NoError(t, err)
		assert.True(t, rep.DryRun)
		assert.Equal(t, 1, rep.Renamed)
		require.Len(t, rep.Outcomes, 1)
		assert.Equal(t, renameStatusWouldRename, rep.Outcomes[0].Status)
		assert.Equal(t, "db-password", rep.Outcomes[0].OldName)
		assert.Equal(t, "DB_PASSWORD", rep.Outcomes[0].NewName)
		// Nothing persisted.
		s, err := c.storage.GetSecret(ctx, bad)
		require.NoError(t, err)
		assert.Equal(t, "db-password", s.Name)
	})

	t.Run("apply renames the secret and audits it", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: bad, NewName: "DB_PASSWORD"}}, false, "alice", 1, "1.2.3.4", "cli")
		require.NoError(t, err)
		assert.False(t, rep.DryRun)
		assert.Equal(t, 1, rep.Renamed)
		assert.Equal(t, renameStatusRenamed, rep.Outcomes[0].Status)
		s, err := c.storage.GetSecret(ctx, bad)
		require.NoError(t, err)
		assert.Equal(t, "DB_PASSWORD", s.Name)
		// An audit event was written for the rename.
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "secret.updated").Count(&n).Error)
		assert.Positive(t, n)
	})

	t.Run("rejects a new name that itself violates the policy", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: bad, NewName: "still-bad"}}, false, "alice", 1, "", "")
		require.NoError(t, err)
		assert.Equal(t, 0, rep.Renamed)
		require.Len(t, rep.Outcomes, 1)
		assert.Equal(t, renameStatusSkipped, rep.Outcomes[0].Status)
		assert.Contains(t, rep.Outcomes[0].Reason, "pattern")
	})

	t.Run("skips a collision with an existing sibling name", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: bad, NewName: "EXISTING_NAME"}}, false, "alice", 1, "", "")
		require.NoError(t, err)
		assert.Equal(t, 0, rep.Renamed)
		assert.Equal(t, renameStatusSkipped, rep.Outcomes[0].Status)
		assert.Contains(t, rep.Outcomes[0].Reason, "already exists")
	})

	t.Run("skips a folder node", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: folder, NewName: "FOLDER_X"}}, false, "alice", 1, "", "")
		require.NoError(t, err)
		assert.Equal(t, 0, rep.Renamed)
		assert.Contains(t, rep.Outcomes[0].Reason, "not a secret")
	})

	t.Run("cross-project guard: cannot rename another project's secret", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: foreign, NewName: "OTHER_SECRET"}}, false, "alice", 1, "", "")
		require.NoError(t, err)
		assert.Equal(t, 0, rep.Renamed)
		assert.Contains(t, rep.Outcomes[0].Reason, "does not belong")
		// Untouched in its own project.
		s, err := c.storage.GetSecret(ctx, foreign)
		require.NoError(t, err)
		assert.Equal(t, "other-secret", s.Name)
	})

	t.Run("missing secret, empty name, and unchanged name are each skipped", func(t *testing.T) {
		rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{
			{ID: 99999, NewName: "GHOST"},
			{ID: bad, NewName: "   "},
			{ID: bad, NewName: "DB_PASSWORD"}, // already renamed to this above → unchanged
		}, false, "alice", 1, "", "")
		require.NoError(t, err)
		assert.Equal(t, 0, rep.Renamed)
		assert.Equal(t, 3, rep.Skipped)
		assert.Contains(t, rep.Outcomes[0].Reason, "not found")
		assert.Contains(t, rep.Outcomes[1].Reason, "empty")
		assert.Contains(t, rep.Outcomes[2].Reason, "unchanged")
	})
}
