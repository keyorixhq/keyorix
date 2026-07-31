package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newRotateNoopFixture builds an in-memory core with a project/environment/secret
// ready for rotation, matching the harness used by TestConcurrency_RotateSecret_*.
// AuditEvent is migrated too since a no-op rotation is expected to audit
// secret.rotate_noop (see rollback_test.go's rollbackCore for the same precedent).
func newRotateNoopFixture(t *testing.T) (*core.KeyorixCore, uint, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "rotated-secret", Value: []byte("initial-secret-value-123"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: 1, CreatedBy: "owner",
	})
	require.NoError(t, err)
	return c, sec.ID, db
}

// TestRotateSecret_SameValue_DoesNotBumpLastRotatedAt is the #408 regression:
// resubmitting the byte-identical value must not reset LastRotatedAt (which would
// otherwise make dashboards/auditors/risk-scoring believe stale credential material
// was "just rotated"), even though the codebase's chosen behavior still writes a new
// version row for audit-trail completeness.
func TestRotateSecret_SameValue_DoesNotBumpLastRotatedAt(t *testing.T) {
	c, secretID, db := newRotateNoopFixture(t)
	ctx := context.Background()

	// First rotation: a genuinely new value, so LastRotatedAt must be set.
	updated, err := c.RotateSecret(ctx, secretID, []byte("rotated-value-A"), "rotator")
	require.NoError(t, err)
	require.NotNil(t, updated.LastRotatedAt)
	firstRotatedAt := *updated.LastRotatedAt

	versionsBefore, err := c.GetSecretVersions(ctx, secretID)
	require.NoError(t, err)

	// Sleep to guarantee a distinguishable timestamp if LastRotatedAt were (wrongly)
	// bumped again below.
	time.Sleep(5 * time.Millisecond)

	// Second "rotation" resubmits the exact same value — must be a no-op for the
	// timestamp, but must still store a new version row.
	updated, err = c.RotateSecret(ctx, secretID, []byte("rotated-value-A"), "rotator")
	require.NoError(t, err, "rotating to an unchanged value must not be refused")
	require.NotNil(t, updated.LastRotatedAt)
	assert.True(t, updated.LastRotatedAt.Equal(firstRotatedAt),
		"LastRotatedAt must NOT be bumped when the new value is byte-identical to the current version")

	versionsAfter, err := c.GetSecretVersions(ctx, secretID)
	require.NoError(t, err)
	assert.Len(t, versionsAfter, len(versionsBefore)+1,
		"a new version row must still be stored for audit-trail completeness even on a no-op rotation")

	// The no-op is auditable rather than fully silent.
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", core.EventSecretRotateNoop).Count(&n).Error)
	assert.Equal(t, int64(1), n, "exactly one secret.rotate_noop event should be recorded")

	// A subsequent rotation to a genuinely different value must resume bumping
	// LastRotatedAt normally.
	time.Sleep(5 * time.Millisecond)
	updated, err = c.RotateSecret(ctx, secretID, []byte("rotated-value-B"), "rotator")
	require.NoError(t, err)
	require.NotNil(t, updated.LastRotatedAt)
	assert.True(t, updated.LastRotatedAt.After(firstRotatedAt),
		"LastRotatedAt must be bumped again once the value genuinely changes")
}

// TestRotateSecret_DifferentValue_AlwaysBumpsLastRotatedAt is the companion positive
// case: an ordinary rotation to a new value must behave exactly as before this change.
func TestRotateSecret_DifferentValue_AlwaysBumpsLastRotatedAt(t *testing.T) {
	c, secretID, _ := newRotateNoopFixture(t)
	ctx := context.Background()

	before, err := c.GetSecret(ctx, secretID)
	require.NoError(t, err)
	assert.Nil(t, before.LastRotatedAt, "a freshly created secret has never been rotated")

	updated, err := c.RotateSecret(ctx, secretID, []byte("a-genuinely-different-value"), "rotator")
	require.NoError(t, err)
	require.NotNil(t, updated.LastRotatedAt)
}
