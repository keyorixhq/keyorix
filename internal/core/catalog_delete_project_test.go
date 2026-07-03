package core_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// --- #313 structural regression -------------------------------------------------
//
// DeleteProject's non-force guard (count-then-reject) used to run as a separate
// top-level storage call, entirely before — not inside — the cascade delete's own
// transaction. A secret created in that window silently got swept into the cascade
// despite the caller expecting the delete to be rejected. The fix runs the guard and
// the cascade inside one storage.WithTransaction call, so the count the guard acts on
// is read from, and committed alongside, the exact same transaction as the delete.
//
// deleteProjectOuterSpy/deleteProjectTxSpy assert that structurally: the outer spy
// implements only WithTransaction (every other storage.Storage method is left on a
// nil-embedded interface, so calling one panics on a nil pointer dereference) — so if
// DeleteProject ever again calls ListSecrets or DeleteProject directly on the
// non-transactional outer storage instead of the tx-scoped one WithTransaction hands
// it, this test fails loudly instead of silently passing.

type deleteProjectOuterSpy struct {
	storage.Storage // left nil: any method besides WithTransaction panics if reached
	txCalled        bool
	tx              *deleteProjectTxSpy
}

func (s *deleteProjectOuterSpy) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	s.txCalled = true
	return fn(s.tx)
}

type deleteProjectTxSpy struct {
	storage.Storage // left nil: any method besides the two below panics if reached
	listSecretsTotal int64
	listSecretsErr   error
	deleteErr        error
	callOrder        []string
}

func (s *deleteProjectTxSpy) ListSecrets(_ context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	s.callOrder = append(s.callOrder, "ListSecrets")
	if filter.ProjectID == nil || *filter.ProjectID != 7 {
		return nil, 0, fmt.Errorf("unexpected filter: %+v", filter)
	}
	return nil, s.listSecretsTotal, s.listSecretsErr
}

func (s *deleteProjectTxSpy) DeleteProject(_ context.Context, id uint) error {
	s.callOrder = append(s.callOrder, "DeleteProject")
	if id != 7 {
		return fmt.Errorf("unexpected project id %d", id)
	}
	return s.deleteErr
}

func TestDeleteProject_GuardAndCascadeRunInSameTransaction(t *testing.T) {
	tx := &deleteProjectTxSpy{listSecretsTotal: 0}
	outer := &deleteProjectOuterSpy{tx: tx}
	c := core.NewKeyorixCore(outer)

	require.NoError(t, c.DeleteProject(context.Background(), 7, false))
	assert.True(t, outer.txCalled, "DeleteProject must run inside storage.WithTransaction")
	assert.Equal(t, []string{"ListSecrets", "DeleteProject"}, tx.callOrder,
		"the guard read must happen before the cascade delete, both on the tx-scoped storage")
}

func TestDeleteProject_RejectsWithinTransactionWhenSecretsExist(t *testing.T) {
	tx := &deleteProjectTxSpy{listSecretsTotal: 3}
	outer := &deleteProjectOuterSpy{tx: tx}
	c := core.NewKeyorixCore(outer)

	err := c.DeleteProject(context.Background(), 7, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 secret(s)")
	assert.True(t, outer.txCalled, "the guard itself must still run inside the transaction")
	assert.Equal(t, []string{"ListSecrets"}, tx.callOrder,
		"a rejected guard must short-circuit before reaching the cascade delete")
}

func TestDeleteProject_ForceSkipsGuardButStaysTransactional(t *testing.T) {
	tx := &deleteProjectTxSpy{listSecretsTotal: 99} // would reject if the guard ran
	outer := &deleteProjectOuterSpy{tx: tx}
	c := core.NewKeyorixCore(outer)

	require.NoError(t, c.DeleteProject(context.Background(), 7, true))
	assert.True(t, outer.txCalled)
	assert.Equal(t, []string{"DeleteProject"}, tx.callOrder, "force=true must skip the guard entirely")
}

// --- #313 real-storage integration (sequential, deterministic) -------------------
//
// A live goroutine race against the guard's exact microsecond-wide DB window isn't
// reproducible deterministically here: SQLite's deferred transactions don't take a
// write lock until their first write statement, so an external writer can still slip
// a statement in between the guard's read and the cascade's write — the same
// inherent limit acknowledged by the finding itself ("just fix the ordering", not
// eliminate every possible interleaving; the backlog separately calibrates the
// residual risk as no worse than an explicit force=true). Racing a *second*
// independent write path (e.g. CreateSecret) additionally entangles this test with
// that path's own liveness-check timing, which is unrelated to DeleteProject. The
// structural tests above are the precise regression for the actual fix (guard and
// cascade co-located in one transaction); these round it out against real storage.

func TestDeleteProject_RealStorage_RejectsWhenSecretsExist(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, IsSecret: true}).Error)

	err = c.DeleteProject(ctx, 1, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 secret(s)")

	var p models.Project
	require.NoError(t, db.First(&p, 1).Error, "the project must remain live after a rejected delete")
}

func TestDeleteProject_RealStorage_EmptyProjectSucceeds(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)

	require.NoError(t, c.DeleteProject(ctx, 1, false))

	var p models.Project
	err = db.First(&p, 1).Error
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound, "the project must be (soft-)deleted")
}

func TestDeleteProject_RealStorage_ForceCascadesOverSecrets(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, IsSecret: true}).Error)

	require.NoError(t, c.DeleteProject(ctx, 1, true))

	var liveSecrets int64
	require.NoError(t, db.Model(&models.SecretNode{}).Where("project_id = ? AND deleted_at IS NULL", 1).Count(&liveSecrets).Error)
	assert.Zero(t, liveSecrets, "force=true must cascade-delete the secret along with the project")
}
