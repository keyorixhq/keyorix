package store

// LEASE-SHARE-RACE-1 (#2801, #2802): CreateShareRecord's two upsert paths, the
// re-share of an existing live share and the fallback after losing the #136
// create race, both used to persist the row they had read with a full-row Save.
//
// Each test lands a second writer's change between createShareRecordTx's read
// and its write, then asserts the row in the database, never the return value:
//
//   - On Postgres the second writer is a separate connection (its own *gorm.DB
//     pool, the same schema), committing on its own, exactly as another replica
//     would. Replica A's transaction holds no row lock at that point (plain
//     SELECTs), so B never blocks.
//   - SQLite serializes writers (BEGIN IMMEDIATE), so no other connection can
//     commit inside A's transaction and the race cannot happen there in
//     production. The tests still run createShareRecordTx on SQLite: in a
//     transaction the test owns, the change is executed on that transaction at
//     the same point, and the end state is read inside it before it is rolled
//     back (a fail-closed create rolls back, which would take an in-transaction
//     revoke with it). The code under test sees the identical database state (the
//     row revoked, or a competing row present) when it issues its write.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

type shareRaceWorld struct {
	backend string
	ls      *LocalStorage // replica A
	dbA     *gorm.DB
	dbB     *gorm.DB // replica B's own connection (Postgres only)
}

func shareRaceBackends() []string {
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		return []string{"sqlite"}
	}
	return []string{"sqlite", "postgres"}
}

func newShareRaceWorld(t *testing.T, backend string) *shareRaceWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	w := &shareRaceWorld{backend: backend}
	if backend == "sqlite" {
		dsn := "file:" + filepath.Join(t.TempDir(), "share-race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		w.dbA = db
	} else {
		dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
		w.dbA = pgOpen(t, dsn)
		w.dbB = pgOpen(t, dsn)
	}
	require.NoError(t, w.dbA.AutoMigrate(&models.User{}, &models.Group{}, &models.SecretNode{}, &models.ShareRecord{}))
	// The partial unique index the real migration installs (ensureShareRecordUniqueIndex,
	// internal/storage/factory.go; not importable here, see sharingConcurrentDB).
	require.NoError(t, w.dbA.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_share_records_active ON share_records (secret_id, recipient_id, is_group) WHERE deleted_at IS NULL",
	).Error)
	require.NoError(t, w.dbA.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, w.dbA.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	require.NoError(t, w.dbA.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)
	w.ls = NewLocalStorage(w.dbA)
	return w
}

// other runs sql as replica B: on its own connection (Postgres), or on A's
// transaction handle at the interleaving point (SQLite, see the file header).
func (w *shareRaceWorld) other(t *testing.T, aTx *gorm.DB, sql string, args ...any) {
	t.Helper()
	db := w.dbB
	if w.backend == "sqlite" {
		db = aTx.Session(&gorm.Session{NewDB: true})
		db.Error = nil // Session carries the callback statement's error (e.g. ErrRecordNotFound)
	}
	require.NoError(t, db.Exec(sql, args...).Error)
}

// create runs replica A's CreateShareRecord and then inspect against the
// resulting database state; see the file header for the SQLite variant.
func (w *shareRaceWorld) create(t *testing.T, share *models.ShareRecord, inspect func(db *gorm.DB)) (*models.ShareRecord, error) {
	t.Helper()
	if w.backend != "sqlite" {
		got, err := w.ls.CreateShareRecord(context.Background(), share)
		inspect(w.dbB)
		return got, err
	}
	tx := w.dbA.Begin()
	require.NoError(t, tx.Error)
	defer tx.Rollback()
	got, err := createShareRecordTx(tx, share)
	view := tx.Session(&gorm.Session{NewDB: true})
	view.Error = nil
	inspect(view)
	return got, err
}

// onShareRecords registers fn to run once, inside A's transaction, when A's
// statement of kind ("query" after it ran, "update" before it runs) touches
// share_records. Returns whether it fired.
func (w *shareRaceWorld) onShareRecords(t *testing.T, kind string, fn func(aTx *gorm.DB)) func() bool {
	t.Helper()
	var once sync.Once
	hit := false
	cb := func(tx *gorm.DB) {
		if tx.Statement.Table != "share_records" {
			return
		}
		if _, inTx := tx.Statement.ConnPool.(gorm.TxCommitter); !inTx {
			return
		}
		once.Do(func() {
			hit = true
			fn(tx)
		})
	}
	name := "lease-share-race-1:" + kind
	switch kind {
	case "query":
		require.NoError(t, w.dbA.Callback().Query().After("gorm:query").Register(name, cb))
	case "update":
		require.NoError(t, w.dbA.Callback().Update().Before("gorm:update").Register(name, cb))
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	return func() bool { return hit }
}

func shareRow(t *testing.T, db *gorm.DB, id uint) models.ShareRecord {
	t.Helper()
	var r models.ShareRecord
	require.NoError(t, db.Unscoped().First(&r, id).Error)
	return r
}

func liveShares(t *testing.T, db *gorm.DB) []models.ShareRecord {
	t.Helper()
	var rs []models.ShareRecord
	require.NoError(t, db.Where(sqlWhereShareActive, 100, 2, false).Find(&rs).Error)
	return rs
}

// #2802, re-share path: a revoke committed between createShareRecordTx's lookup
// of the existing share and its write must stay revoked.
func TestCreateShareRecord_RevokeBetweenReadAndWrite_StaysRevoked(t *testing.T) {
	for _, backend := range shareRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newShareRaceWorld(t, backend)
			ctx := context.Background()
			orig, err := w.ls.CreateShareRecord(ctx, &models.ShareRecord{SecretID: 100, RecipientID: 2, OwnerID: 1, Permission: "read"})
			require.NoError(t, err)

			revokedAt := time.Now().UTC()
			fired := w.onShareRecords(t, "update", func(aTx *gorm.DB) {
				w.other(t, aTx, "UPDATE share_records SET deleted_at = ? WHERE id = ?", revokedAt, orig.ID)
			})
			exp := time.Now().Add(time.Hour)
			var row models.ShareRecord
			var live []models.ShareRecord
			_, reshareErr := w.create(t, &models.ShareRecord{
				SecretID: 100, RecipientID: 2, OwnerID: 1, Permission: "write", ExpiresAt: &exp,
			}, func(db *gorm.DB) { row, live = shareRow(t, db, orig.ID), liveShares(t, db) })
			require.True(t, fired(), "the revoke never landed between the lookup and the write; the interleaving under test did not happen")

			assert.True(t, row.DeletedAt.Valid, "the revoked share (id %d) must stay revoked; re-share err: %v", orig.ID, reshareErr)
			assert.Equal(t, "read", row.Permission, "the revoked row must not carry the re-share's permission")
			assert.Empty(t, live, "no live share may exist: the re-share lost to the revoke and must not grant anything")
			require.Error(t, reshareErr, "a re-share whose row was revoked underneath it must fail closed, not report success")
			assert.True(t, errors.Is(reshareErr, storage.ErrShareNotFound), "want ErrShareNotFound, got %v", reshareErr)
		})
	}
}

// #2801, lost-race path: a time-bound share that loses the create race to a
// permanent one must still come back time-bound, with the caller's expiry.
func TestCreateShareRecord_LostCreateRace_KeepsCallerExpiry(t *testing.T) {
	for _, backend := range shareRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newShareRaceWorld(t, backend)

			// A's lookup misses; B's permanent read share commits before A's INSERT.
			fired := w.onShareRecords(t, "query", func(aTx *gorm.DB) {
				w.other(t, aTx,
					"INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
					100, 1, 2, false, "read", time.Now().UTC(), time.Now().UTC())
			})
			exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			var live []models.ShareRecord
			got, err := w.create(t, &models.ShareRecord{
				SecretID: 100, RecipientID: 2, OwnerID: 1, Permission: "write", ExpiresAt: &exp,
			}, func(db *gorm.DB) { live = liveShares(t, db) })
			require.True(t, fired(), "the competing create never landed between the lookup and the INSERT")
			require.NoError(t, err)

			require.Len(t, live, 1, "the lost race must collapse onto the winner's row")
			require.NotNil(t, live[0].ExpiresAt, "a 1-hour share that lost the create race came back permanent (#2801)")
			assert.WithinDuration(t, exp, *live[0].ExpiresAt, time.Second, "the persisted expiry must be the caller's")
			assert.Equal(t, "write", live[0].Permission)
			assert.Equal(t, live[0].ID, got.ID)
		})
	}
}

// #2802, lost-race path: the winner's row revoked between the fallback's lookup
// and its write stays revoked, and the call fails closed.
func TestCreateShareRecord_LostCreateRace_WinnerRevoked_StaysRevoked(t *testing.T) {
	for _, backend := range shareRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newShareRaceWorld(t, backend)

			fired := w.onShareRecords(t, "query", func(aTx *gorm.DB) {
				w.other(t, aTx,
					"INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
					100, 1, 2, false, "read", time.Now().UTC(), time.Now().UTC())
			})
			revoked := w.onShareRecords(t, "update", func(aTx *gorm.DB) {
				w.other(t, aTx, "UPDATE share_records SET deleted_at = ? WHERE secret_id = ? AND recipient_id = ? AND deleted_at IS NULL", time.Now().UTC(), 100, 2)
			})
			exp := time.Now().Add(time.Hour)
			var live []models.ShareRecord
			_, err := w.create(t, &models.ShareRecord{
				SecretID: 100, RecipientID: 2, OwnerID: 1, Permission: "write", ExpiresAt: &exp,
			}, func(db *gorm.DB) { live = liveShares(t, db) })
			require.True(t, fired(), "the competing create never landed")
			require.True(t, revoked(), "the revoke never landed between the fallback lookup and its write")

			assert.Empty(t, live, "the revoked winner must stay revoked (err: %v)", err)
			assert.True(t, errors.Is(err, storage.ErrShareNotFound), "want ErrShareNotFound, got %v", err)
		})
	}
}
