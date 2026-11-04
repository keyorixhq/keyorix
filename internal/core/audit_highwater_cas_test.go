// audit_highwater_cas_test.go — the audit high-water mark and the signed
// verification state survive two holders of WithAuditCheckpointLock
// (AUDIT-HIGHWATER-CAS-1, docs/design/pooler-lock-loss.md row 15).
//
// A silent lock loss lets a second replica take the lock while the first is
// still inside its section. Both read the row, then both write it. With a
// last-write-wins upsert the slower writer's older value replaced the faster
// one's: a lower high-water mark (a later truncation of the newest events goes
// unseen) or a state without the failure the other holder just recorded. Each
// case uses two cores on separate connection pools into one database and stops
// the slower one between its read and its write.
//
// Every case runs on SQLite (one file, production pragmas) and, with
// KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// hwCASPair is two replicas (a and b) over their own pools into one database.
type hwCASPair struct {
	a, b       *KeyorixCore
	dbA, dbB   *gorm.DB
	setup      *gorm.DB
	clk        *incrClock
	newReplica func() (*KeyorixCore, *gorm.DB)
}

func hwCASRun(t *testing.T, body func(t *testing.T, p *hwCASPair)) {
	t.Helper()
	backends := []struct {
		name string
		open func(t *testing.T) func() *gorm.DB
	}{
		{"sqlite", func(t *testing.T) func() *gorm.DB {
			path := filepath.Join(t.TempDir(), "hw-cas.db")
			return func() *gorm.DB {
				db, err := gorm.Open(sqlite.Open("file:"+path+sqliteProdPragmas), &gorm.Config{Logger: logger.Discard})
				require.NoError(t, err)
				t.Cleanup(func() {
					if sqlDB, err := db.DB(); err == nil {
						_ = sqlDB.Close()
					}
				})
				return db
			}
		}},
		{"postgres", func(t *testing.T) func() *gorm.DB {
			dsn := pgJobLockDSN(t)
			return func() *gorm.DB { return pgOpen(t, dsn) }
		}},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			open := b.open(t)
			setup := open()
			require.NoError(t, setup.AutoMigrate(
				&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
			))
			clk := &incrClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
			p := &hwCASPair{setup: setup, clk: clk}
			p.newReplica = func() (*KeyorixCore, *gorm.DB) {
				db := open()
				return restartCore(t, store.NewLocalStorage(db), clk, true), db
			}
			p.a, p.dbA = p.newReplica()
			p.b, p.dbB = p.newReplica()
			body(t, p)
		})
	}
}

// pauseAfterMetadataRead stops db's goroutine right after its first read of
// system_metadata key: reached is closed, then it waits for release. The read
// has completed (rows scanned, no lock held), so the other replica can write.
func pauseAfterMetadataRead(t *testing.T, db *gorm.DB, key string) (reached, release chan struct{}) {
	t.Helper()
	reached, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	name := "hw-cas:pause-" + key
	require.NoError(t, db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table != "system_metadata" || !slices.Contains(tx.Statement.Vars, any(key)) {
			return
		}
		once.Do(func() {
			close(reached)
			<-release
		})
	}))
	return reached, release
}

func hwCASCheckpoint(n int64) *models.AuditCheckpoint {
	return &models.AuditCheckpoint{ChainedEvents: n, HeadID: uint(n), HeadHash: fmt.Sprintf("%064x", n), KeyVersion: "v1"}
}

// storedHighWater returns the stored mark's count, asserting that it
// authenticates under c's key and seal binding.
func storedHighWater(t *testing.T, c *KeyorixCore, db *gorm.DB) int64 {
	t.Helper()
	cp, sig, ok := c.parseAuditHighWaterBound(untrustedMeta(t, db, auditHighWaterKey))
	require.True(t, ok, "the stored high-water mark parses")
	require.True(t, c.checkpointSigMatches(cp, sig), "the stored high-water mark is signed under the current key and seal binding")
	return cp.ChainedEvents
}

// Two holders advance the mark: the slower one read the floor before the
// faster one wrote a higher mark. The stored mark must be the HIGHER
// checkpoint afterwards, whether a mark existed before or not.
func TestAuditHighWaterCAS_SlowerHolderNeverLowersTheMark(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial int64 // 0: no mark yet
	}{
		{"absent", 0},
		{"present", 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hwCASRun(t, func(t *testing.T, p *hwCASPair) {
				ctx := context.Background()
				if tc.initial > 0 {
					p.a.advanceAuditHighWater(ctx, hwCASCheckpoint(tc.initial))
					require.Equal(t, tc.initial, storedHighWater(t, p.a, p.setup))
					p.a, p.dbA = p.newReplica()
					p.b, p.dbB = p.newReplica()
				}
				reached, release := pauseAfterMetadataRead(t, p.dbB, auditHighWaterKey)
				done := make(chan struct{})
				go func() {
					defer close(done)
					p.b.advanceAuditHighWater(ctx, hwCASCheckpoint(100)) // slower holder, lower checkpoint
				}()
				<-reached
				p.a.advanceAuditHighWater(ctx, hwCASCheckpoint(200)) // faster holder, higher checkpoint
				require.Equal(t, int64(200), storedHighWater(t, p.a, p.setup))
				close(release)
				<-done

				assert.Equal(t, int64(200), storedHighWater(t, p.a, p.setup),
					"the slower holder's lower checkpoint must not replace the higher mark")
				assert.Equal(t, int64(200), p.b.watermark(), "the slower holder raises its in-memory floor to the mark it lost to")
			})
		})
	}
}
