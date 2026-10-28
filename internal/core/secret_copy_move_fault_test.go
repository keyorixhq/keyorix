package core

// secret_copy_move_fault_test.go — ERRLOSS-SENTINELS-1: the copy and move paths
// tell a missing secret from a storage failure by the storage.ErrSecretNotFound
// sentinel. A GetSecret that fails with a driver error must surface as that
// error — never as "not found" (which the transports answer 404), never as a
// refused read (which would write a refusal audit row for a read nobody was
// denied) — and must leave the data untouched. The fault is injected with
// internal/faultstorage over a real LocalStorage.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCopySecret_SourceReadFaultIsNotNotFoundAndWritesNoRefusalRow(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	base := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: base, now: time.Now}
	ctx := context.Background()
	p1, err := base.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	staging, err := base.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	require.NoError(t, err)
	prod, err := base.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p1.ID}).Error)
	src, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db-url", Value: []byte("postgres://secret"), ProjectID: p1.ID, EnvironmentID: staging.ID,
		Type: "connection-string", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	var before int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("secret_node_id = ?", src.ID).Count(&before).Error)

	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: GetSecret"),
	})
	fc := &KeyorixCore{storage: fs, now: time.Now}
	copied, err := fc.CopySecret(ctx, src.ID, prod.ID, "", "owner", 1, "203.0.113.5", "test-agent/1.0")

	require.True(t, fs.Fired(), "the source read must have reached the faulted GetSecret")
	require.Error(t, err)
	assert.Nil(t, copied)
	assert.False(t, storage.IsSecretNotFound(err), "a storage failure must not read as \"no such secret\": %v", err)
	assert.Contains(t, err.Error(), "injected: GetSecret")

	var after int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("secret_node_id = ?", src.ID).Count(&after).Error)
	assert.Equal(t, before, after, "no secret.read refusal row for a read that was never refused")
	var copies int64
	require.NoError(t, db.Model(&models.SecretNode{}).Where("environment_id = ?", prod.ID).Count(&copies).Error)
	assert.Zero(t, copies, "nothing was copied")

	// Calibration: the same copy without the fault succeeds.
	_, err = c.CopySecret(ctx, src.ID, prod.ID, "", "owner", 1, "203.0.113.5", "test-agent/1.0")
	require.NoError(t, err)
}

// MoveSecret reads the secret and then the destination parent (and the guards
// before them read it too). Faulting each GetSecret call in turn must never turn
// a driver error into "not found" nor move the secret.
func TestMoveSecret_ParentSetGetSecretFaultIsNotNotFoundAndMovesNothing(t *testing.T) {
	t.Parallel()
	fired := 0
	for nth := 1; nth <= 4; nth++ {
		c, secretID, folderID, db := newMoveFixture(t)
		fs := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
			Method: "GetSecret", NthCall: nth, Kind: faultstorage.KindError,
			Err: errors.New("injected: GetSecret"),
		})
		fc := &KeyorixCore{storage: fs, now: time.Now}

		moved, err := fc.MoveSecret(context.Background(), 1, secretID, &folderID)
		if !fs.Fired() {
			continue // fewer than nth GetSecret calls on this path
		}
		fired++
		require.Error(t, err, "GetSecret call %d faulted: the move must fail", nth)
		assert.Nil(t, moved)
		assert.False(t, storage.IsSecretNotFound(err), "call %d: a storage failure must not read as not-found: %v", nth, err)

		var row models.SecretNode
		require.NoError(t, db.First(&row, secretID).Error)
		assert.Nil(t, row.ParentID, "call %d: the secret must not have been moved", nth)
		var moves int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("secret_node_id = ? AND event_type = ?", secretID, EventSecretMoved).Count(&moves).Error)
		assert.Zero(t, moves, "call %d: no secret.moved row for a move that did not happen", nth)
	}
	require.GreaterOrEqual(t, fired, 2, "both the secret read and the parent read must be reachable by a GetSecret fault")
}
