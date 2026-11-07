package storage

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// TestFactoryReplicas_FileDBHasNoWriteErrorsUnderConcurrentReads guards the production shape for
// a two-replica test world: two storages from the production factory on one database
// file (WAL), a writer on A and readers on B, where no write may fail.
//
// It used to carry a control showing that the shared-cache DSN (sqlitetest.DSN) fails
// the same load with "database table is locked" (SQLITE_LOCKED, 262): that is why
// tests hand the factory sqlitetest.FactoryPath (merge-queue run 40142034894). The
// control was retired when modernc.org/sqlite v1.61.0 made shared-cache BeginTx wait
// for the lock instead of failing with 262, so it no longer demonstrates anything.
// The FactoryPath guidance stands: a shared cache is still not the production shape.
func TestFactoryReplicas_FileDBHasNoWriteErrorsUnderConcurrentReads(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	run := func(t *testing.T, path string) (writes, locked int64, firstLockErr string) {
		t.Helper()
		cfg := &config.Config{}
		cfg.Storage.Type = "local"
		cfg.Storage.Database.Path = path
		open := func() *store.LocalStorage {
			st, err := NewStorageFactory().CreateStorage(cfg)
			require.NoError(t, err)
			ls, ok := st.(*store.LocalStorage)
			require.True(t, ok, "%T", st)
			t.Cleanup(func() { _ = ls.Close() })
			return ls
		}
		a, b := open(), open()
		require.NoError(t, a.DB().Exec("CREATE TABLE lock_probe_a (id INTEGER PRIMARY KEY, v INTEGER)").Error)
		require.NoError(t, a.DB().Exec("CREATE TABLE lock_probe_b (id INTEGER PRIMARY KEY, v INTEGER)").Error)

		stop := make(chan struct{})
		var wg sync.WaitGroup
		var readErrs atomic.Int64
		for range 4 {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					// A read transaction over both tables, in the opposite order to the
					// writer's: what a request on replica B does while A writes.
					err := b.DB().Transaction(func(tx *gorm.DB) error {
						var n int64
						if err := tx.Raw("SELECT count(*) FROM lock_probe_b").Scan(&n).Error; err != nil {
							return err
						}
						return tx.Raw("SELECT count(*) FROM lock_probe_a").Scan(&n).Error
					})
					if err != nil {
						readErrs.Add(1)
					}
				}
			})
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			// One write transaction over two tables, like AddProjectMember's.
			err := a.DB().Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec("INSERT INTO lock_probe_a (v) VALUES (1)").Error; err != nil {
					return err
				}
				return tx.Exec("INSERT INTO lock_probe_b (v) VALUES (1)").Error
			})
			switch {
			case err == nil:
				writes++
			case strings.Contains(err.Error(), "locked"):
				if locked == 0 {
					firstLockErr = err.Error()
				}
				locked++
			default:
				t.Fatalf("unexpected write error: %v", err)
			}
		}
		close(stop)
		wg.Wait()
		t.Logf("%d writes, %d failed with a lock error (first: %q), %d reads failed", writes, locked, firstLockErr, readErrs.Load())
		return writes, locked, firstLockErr
	}

	t.Run("file (FactoryPath): no write fails", func(t *testing.T) {
		writes, locked, _ := run(t, sqlitetest.FactoryPath(t, "replicas_lock_probe"))
		require.Zero(t, locked)
		require.Positive(t, writes)
	})
}
