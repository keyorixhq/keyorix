// local_secrets_zero_coverage_test.go covers local_secrets.go functions that
// were still at 0%: GetProjectByName, ClearProjectSecretOwnership,
// GetSecretAncestors.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newSecretsZeroCoverageStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.SecretNode{}, &models.Environment{}))
	return NewLocalStorage(db)
}

func TestGetProjectByName_CaseInsensitive(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	db := ls.DB()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "MyProject"}).Error)

	got, err := ls.GetProjectByName(context.Background(), "myproject")
	require.NoError(t, err)
	assert.Equal(t, uint(1), got.ID)

	got, err = ls.GetProjectByName(context.Background(), "MYPROJECT")
	require.NoError(t, err)
	assert.Equal(t, uint(1), got.ID)
}

func TestGetProjectByName_NotFound(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	project, err := ls.GetProjectByName(context.Background(), "nope")
	require.Error(t, err)
	assert.Nil(t, project)
}

func TestClearProjectSecretOwnership(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "s1", IsSecret: true, Status: "active", OwnerID: 42}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "s2", IsSecret: true, Status: "active", OwnerID: 42}).Error)
	// Different project, same owner -- must be untouched.
	require.NoError(t, db.Create(&models.SecretNode{ID: 3, ProjectID: 2, EnvironmentID: 1, Name: "s3", IsSecret: true, Status: "active", OwnerID: 42}).Error)
	// Same project, different owner -- must be untouched.
	require.NoError(t, db.Create(&models.SecretNode{ID: 4, ProjectID: 1, EnvironmentID: 1, Name: "s4", IsSecret: true, Status: "active", OwnerID: 7}).Error)

	require.NoError(t, ls.ClearProjectSecretOwnership(ctx, 42, 1))

	var s1, s2, s3, s4 models.SecretNode
	require.NoError(t, db.First(&s1, 1).Error)
	require.NoError(t, db.First(&s2, 2).Error)
	require.NoError(t, db.First(&s3, 3).Error)
	require.NoError(t, db.First(&s4, 4).Error)

	assert.Zero(t, s1.OwnerID)
	assert.Zero(t, s2.OwnerID)
	assert.Equal(t, uint(42), s3.OwnerID, "a different project's secret owned by the same user must be untouched")
	assert.Equal(t, uint(7), s4.OwnerID, "a different owner's secret in the same project must be untouched")
}

func TestClearProjectSecretOwnership_NoMatchIsNoop(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	require.NoError(t, ls.ClearProjectSecretOwnership(context.Background(), 404, 404))
}

func TestGetSecretAncestors_WalksUpToRoot(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "root", IsSecret: false, Status: "active"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "mid", IsSecret: false, Status: "active", ParentID: uptr(1)}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 3, ProjectID: 1, EnvironmentID: 1, Name: "leaf", IsSecret: true, Status: "active", ParentID: uptr(2)}).Error)

	ancestors, err := ls.GetSecretAncestors(ctx, 3)
	require.NoError(t, err)
	assert.Equal(t, []uint{2, 1}, ancestors)
}

func TestGetSecretAncestors_RootHasNoAncestors(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	ctx := context.Background()
	db := ls.DB()
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "root", IsSecret: false, Status: "active"}).Error)

	ancestors, err := ls.GetSecretAncestors(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, ancestors)
}

func TestGetSecretAncestors_MissingNodeStopsWalk(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	ancestors, err := ls.GetSecretAncestors(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, ancestors)
}

// A parent cycle (data corruption, or a defensive test of the guard itself)
// must not hang the walk -- the visited-set cycle guard breaks out instead.
func TestGetSecretAncestors_CycleGuardStopsInfiniteLoop(t *testing.T) {
	ls := newSecretsZeroCoverageStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "a", IsSecret: false, Status: "active", ParentID: uptr(2)}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "b", IsSecret: false, Status: "active", ParentID: uptr(1)}).Error)

	done := make(chan struct{})
	var ancestors []uint
	var err error
	go func() {
		ancestors, err = ls.GetSecretAncestors(ctx, 1)
		close(done)
	}()
	select {
	case <-done:
		require.NoError(t, err)
		assert.NotEmpty(t, ancestors, "the cycle must be walked at least once before the guard breaks it")
	case <-time.After(5 * time.Second):
		t.Fatal("GetSecretAncestors did not return -- the cycle guard failed to stop an infinite loop")
	}
}
