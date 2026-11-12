package core

// #3944: a retention purge that ran while VerifyAuditChain walked a chain longer
// than one store batch, removing rows past the walk's cursor, made the valid
// surviving chain read broken ("prev_hash does not link to the preceding
// event"). The chain is now walked once more from the moved, authenticated
// anchor, and the checkpoint comparison uses that anchor's purged count. A
// delete outside a purge and a tamper in the same window stay broken.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// More than one store walk batch (1000 rows) is old enough to purge.
const purgeOvertakeOld, purgeOvertakeNew = 1003, 2

type purgeOvertakeEnv struct {
	c  *KeyorixCore
	db *gorm.DB
	// recent are the rows the 30-day purge keeps.
	recent []*models.AuditEvent
}

func newPurgeOvertakeEnv(t *testing.T, db *gorm.DB) *purgeOvertakeEnv {
	t.Helper()
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.now = func() time.Time { return fixed }
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	env := &purgeOvertakeEnv{c: c, db: db}
	start := fixed.AddDate(0, 0, -40)
	for i := range purgeOvertakeOld {
		logChainedEvent(t, c, "secret.read", start.Add(time.Duration(i)*time.Second))
	}
	for i := range purgeOvertakeNew {
		env.recent = append(env.recent, logChainedEvent(t, c, "secret.read", fixed.Add(-time.Hour+time.Duration(i)*time.Second)))
	}
	return env
}

// duringWalk runs fn once, right after the walk's first full batch read.
func (e *purgeOvertakeEnv) duringWalk(t *testing.T, fn func()) *atomic.Bool {
	t.Helper()
	var fired atomic.Bool
	require.NoError(t, e.db.Callback().Query().After("gorm:query").Register("test:during_walk", func(tx *gorm.DB) {
		if batch, ok := tx.Statement.Dest.(*[]*models.AuditEvent); ok && len(*batch) == 1000 && fired.CompareAndSwap(false, true) {
			fn()
		}
	}))
	return &fired
}

// purgeDuringWalk lands the real PurgeAuditLogs inside the walk, removing every
// old row, the next batch's first rows included.
func (e *purgeOvertakeEnv) purgeDuringWalk(t *testing.T) *atomic.Bool {
	return e.duringWalk(t, func() {
		res, err := e.c.PurgeAuditLogs(context.Background(), AuditLogRetentionConfig{RetentionDays: 30})
		require.NoError(t, err)
		require.Equal(t, int64(purgeOvertakeOld), res.DeletedCount)
	})
}

func testVerifyWithPurgeOvertakingWalk(t *testing.T, open func(*testing.T) *gorm.DB) {
	ctx := context.Background()
	for _, checkpoint := range []bool{false, true} {
		name := "no checkpoint"
		if checkpoint {
			name = "checkpoint certified before the purge"
		}
		t.Run("a sanctioned purge in the window reads valid: "+name, func(t *testing.T) {
			env := newPurgeOvertakeEnv(t, open(t))
			if checkpoint {
				_, written, err := env.c.WriteAuditCheckpoint(ctx)
				require.NoError(t, err)
				require.True(t, written)
			}
			fired := env.purgeDuringWalk(t)
			v, err := env.c.VerifyAuditChain(ctx)
			require.NoError(t, err)
			require.True(t, fired.Load(), "test bug: the purge never ran inside the walk")
			assert.True(t, v.Valid, v.Reason)
			assert.Empty(t, v.CheckpointReason)
			// The two survivors and the purge's own audit event. With a
			// checkpoint this also needs the moved anchor's purged count.
			assert.Equal(t, int64(purgeOvertakeNew+1), v.ChainedEvents)
		})
	}
	t.Run("a delete outside a purge in the window stays broken", func(t *testing.T) {
		env := newPurgeOvertakeEnv(t, open(t))
		env.duringWalk(t, func() {
			require.NoError(t, env.db.Session(&gorm.Session{NewDB: true}).
				Exec(`DELETE FROM audit_events WHERE id < ?`, env.recent[0].ID).Error)
		})
		v, err := env.c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.False(t, v.Valid)
		assert.Contains(t, v.Reason, "prev_hash does not link")
	})
	t.Run("a tamper in the same window stays broken", func(t *testing.T) {
		env := newPurgeOvertakeEnv(t, open(t))
		tampered := env.recent[1]
		env.duringWalk(t, func() {
			res, err := env.c.PurgeAuditLogs(context.Background(), AuditLogRetentionConfig{RetentionDays: 30})
			require.NoError(t, err)
			require.Positive(t, res.DeletedCount)
			require.NoError(t, env.db.Session(&gorm.Session{NewDB: true}).
				Exec(`UPDATE audit_events SET description = 'rewritten' WHERE id = ?`, tampered.ID).Error)
		})
		v, err := env.c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		require.False(t, v.Valid)
		require.NotNil(t, v.FirstBrokenID)
		assert.Equal(t, tampered.ID, *v.FirstBrokenID)
		assert.Contains(t, v.Reason, "after walking again from the retention re-anchor")
		assert.Contains(t, v.Reason, "event modified")
	})
}

func TestVerifyAuditChain_PurgeOvertakingTheWalkStaysValid(t *testing.T) {
	testVerifyWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		return db
	})
}

func TestVerifyAuditChain_PurgeOvertakingTheWalkStaysValid_Postgres(t *testing.T) {
	testVerifyWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		return pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	})
}
