// rotate_delete_interleaving_test.go — ROTATE-ORPHAN-1 (#2873): what a
// concurrent DeleteSecret leaves behind when it commits in the middle of
// RotateSecret.
//
// RotateSecret writes the new version and the rotation stamp (last_rotated_at)
// in ONE transaction for a secret with no rotation backend, and in TWO for a
// backend-bound secret: the upstream credential may already have been rotated,
// so the version is Keyorix's only record of the live value and must survive
// a failed stamp (see the comment at the write in rotateSecret). A delete can
// therefore commit between the two writes only on the backend-bound path.
//
// Each case pauses replica A's RotateSecret at one point, lets replica B's
// DeleteSecret commit, then releases A and asserts what actually exists: the
// versions of the deleted secret, the error A returned, and what a restore
// shows as the latest version.
//
//   - backend, delete between the version commit and the stamp (the shape in
//     #2873): the version stays (correct, see above), so the error must say so
//     instead of claiming a plain "secret not found".
//   - backend, delete before the version write: the same, and the version is
//     what a restore serves, so the caller must be told it was stored.
//   - no backend, delete inside the version's transaction before the stamp:
//     the stamp matches no row and the whole transaction rolls back, so
//     nothing is stored and "not found" is the whole truth (Postgres only:
//     SQLite's single writer would park B behind A's open transaction).
//
// The Postgres leg runs A and B on two independent pools (two replicas); it is
// skipped without KEYORIX_TEST_PG_DSN. The SQLite leg runs both on one file
// through two LocalStorage instances.
package core

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	rotateDeleteHoldBeforeVersion = "before-version-write"
	rotateDeleteHoldBeforeStamp   = "before-stamp"
)

type rotateDeleteCase struct {
	name     string
	backend  string
	holdAt   string
	sqliteOK bool
	// stored: the rotated value must survive as version 2 and the error must
	// say it was stored; otherwise nothing may be stored.
	stored bool
}

var rotateDeleteCases = []rotateDeleteCase{
	{name: "backend/delete-between-version-and-stamp", backend: "pg", holdAt: rotateDeleteHoldBeforeStamp, sqliteOK: true, stored: true},
	{name: "backend/delete-before-version-write", backend: "pg", holdAt: rotateDeleteHoldBeforeVersion, sqliteOK: true, stored: true},
	{name: "no-backend/delete-inside-version-tx", backend: "", holdAt: rotateDeleteHoldBeforeStamp, sqliteOK: false, stored: false},
}

// rotateDeleteHold pauses the first matching storage call of replica A once.
type rotateDeleteHold struct {
	secretID         uint
	arm              atomic.Bool
	blocked, release chan struct{}
}

func (h *rotateDeleteHold) pause(id uint) {
	if id == h.secretID && h.arm.CompareAndSwap(true, false) {
		close(h.blocked)
		<-h.release
	}
}

func (h *rotateDeleteHold) wrap(inner storage.Storage, at string) storage.Storage {
	hooks := &storeHooks{WrapTx: true}
	switch at {
	case rotateDeleteHoldBeforeVersion:
		hooks.CreateSecretVersion = func(next storage.Storage, ctx context.Context, v *models.SecretVersion) (*models.SecretVersion, error) {
			h.pause(v.SecretNodeID)
			return next.CreateSecretVersion(ctx, v)
		}
	case rotateDeleteHoldBeforeStamp:
		hooks.UpdateSecretFields = func(next storage.Storage, ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
			h.pause(id)
			return next.UpdateSecretFields(ctx, id, f)
		}
	}
	return hooked(inner, hooks)
}

func seedRotateDeleteSecret(t *testing.T, db *gorm.DB, backend string) uint {
	t.Helper()
	p := models.Project{Name: "rotate-orphan"}
	require.NoError(t, db.Create(&p).Error)
	env := models.Environment{ProjectID: p.ID, Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	s := models.SecretNode{
		Name: "upstream-cred", ProjectID: p.ID, EnvironmentID: env.ID, IsSecret: true, Status: "active",
		Type: "password", Classification: "internal", RotationBackend: backend, RotationRef: "app_svc",
	}
	require.NoError(t, db.Create(&s).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: time.Now(),
	}).Error)
	return s.ID
}

// runRotateDeleteInterleaving drives one case: A = RotateSecret on stA (held),
// B = DeleteSecret on stB, both over the same database.
func runRotateDeleteInterleaving(t *testing.T, tc rotateDeleteCase, db *gorm.DB, stA, stB storage.Storage) {
	t.Helper()
	ctx := context.Background()
	id := seedRotateDeleteSecret(t, db, tc.backend)

	hold := &rotateDeleteHold{secretID: id, blocked: make(chan struct{}), release: make(chan struct{})}
	hold.arm.Store(true)
	coreA := NewKeyorixCore(hold.wrap(stA, tc.holdAt))
	coreB := NewKeyorixCore(stB)

	const rotated = "rotated-upstream-value"
	var rotErr error
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, rotErr = coreA.RotateSecret(ctx, id, []byte(rotated), 0, "system:auto-rotation")
	}()

	select {
	case <-hold.blocked:
	case <-doneA:
		t.Fatalf("RotateSecret returned before reaching the hold point %q: %v", tc.holdAt, rotErr)
	case <-time.After(30 * time.Second):
		t.Fatalf("RotateSecret never reached the hold point %q", tc.holdAt)
	}

	// B: the delete commits while A is parked.
	require.NoError(t, coreB.DeleteSecret(ctx, id), "the concurrent delete must commit while the rotation is held")

	close(hold.release)
	select {
	case <-doneA:
	case <-time.After(30 * time.Second):
		t.Fatal("RotateSecret did not finish after release")
	}

	// The error A returned.
	require.Error(t, rotErr, "the secret was deleted underneath the rotation; it cannot report a clean success")
	assert.ErrorIs(t, rotErr, storage.ErrSecretNotFound, "the secret is gone: still a not-found (HTTP 404) to the caller")

	// The versions of the deleted secret.
	var versions []models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", id).Order("version_number").Find(&versions).Error)

	if !tc.stored {
		assert.Len(t, versions, 1, "a one-transaction rotation must roll its version back when the stamp finds the secret deleted")
		assert.NotContains(t, rotErr.Error(), "stored", "nothing was stored, so the error must not say a value was")
		assert.NotErrorIs(t, rotErr, ErrRotatedValueStoredSecretDeleted)
		return
	}

	require.Len(t, versions, 2, "a backend-bound rotation keeps its version: it may be the only record of the live upstream value")
	assert.Equal(t, rotated, string(versions[1].EncryptedValue))
	assert.ErrorIs(t, rotErr, ErrRotatedValueStoredSecretDeleted, "classifiable without matching the message text")
	assert.Contains(t, rotErr.Error(), "stored as version 2",
		"the caller must learn the rotated value WAS stored (and which version) even though the secret was deleted underneath (#2873)")

	// What a restore shows as latest.
	require.NoError(t, stB.RestoreSecret(ctx, id))
	latest, err := stB.GetLatestSecretVersion(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, 2, latest.VersionNumber, "a restore serves the rotated version as latest")
	assert.Equal(t, rotated, string(latest.EncryptedValue))
}

func TestRotateSecret_ConcurrentDelete_Interleavings_SQLite(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	for _, tc := range rotateDeleteCases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.sqliteOK {
				t.Skip("not expressible on SQLite: A holds the single write transaction, so B's delete cannot commit while A is held (the Postgres leg covers it)")
			}
			dsn := "file:" + filepath.Join(t.TempDir(), "rotate_delete.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
			require.NoError(t, err)
			require.NoError(t, kxstorage.MigrateExisting(db))
			runRotateDeleteInterleaving(t, tc, db, store.NewLocalStorage(db), store.NewLocalStorage(db))
		})
	}
}

func TestRotateSecret_ConcurrentDelete_Interleavings_CrossReplicaPostgres(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	for _, tc := range rotateDeleteCases {
		t.Run(tc.name, func(t *testing.T) {
			dsn := pgMigratedDatabaseDSN(t, base)
			dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
			runRotateDeleteInterleaving(t, tc, dbA, store.NewLocalStorage(dbA), store.NewLocalStorage(dbB))
		})
	}
}

// TestRunAutoRotation_SecretDeletedDuringRotation_AuditsStoredNotDrift: the
// auto-rotation driver's audit for the #2873 interleaving. The backend rotated
// upstream and the new value WAS stored; only the stamp found the secret
// deleted. The audit must say the value was stored, not report DRIFT ("storing
// the new value failed"), which would send an operator to reconcile a
// credential Keyorix already holds.
func TestRunAutoRotation_SecretDeletedDuringRotation_AuditsStoredNotDrift(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	require.NoError(t, db.AutoMigrate(&models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}))
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))
	var armed atomic.Bool
	armed.Store(true)
	c.storage = hooked(c.storage, &storeHooks{
		UpdateSecretFields: func(next storage.Storage, ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
			if armed.CompareAndSwap(true, false) {
				// A concurrent DeleteSecret commits between the version write and the stamp.
				require.NoError(t, next.DeleteSecret(ctx, id))
			}
			return next.UpdateSecretFields(ctx, id, f)
		},
	})

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "the secret was deleted under the rotation: not a clean success")
	require.True(t, fake.called)

	var versions []models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", 1).Order("version_number").Find(&versions).Error)
	require.Len(t, versions, 2, "the rotated value is stored")
	assert.Equal(t, fake.gotVal, string(versions[1].EncryptedValue))

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretAutoRotated).Find(&events).Error)
	require.Len(t, events, 1)
	assert.NotContains(t, events[0].Description, "DRIFT", "the value was stored: this is not drift")
	assert.Contains(t, events[0].Description, "new value was stored")
	assert.Contains(t, events[0].Description, "deleted during the rotation")
	assert.Contains(t, events[0].Description, "version 2")
}
