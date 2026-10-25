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

// TestFactoryReplicas_SharedCacheLocksAndFileDoesNot is why tests hand the factory
// sqlitetest.FactoryPath and never sqlitetest.DSN: two storages from the production
// factory on one database (a two-replica test world), a writer on A and readers on B.
// On the shared-cache DSN the writer fails with "database table is locked" (SQLITE_LOCKED,
// 262) whenever a reader holds the table, at once, past the DSN's 30 s busy timeout:
// TestEveryRouteRefusesADeadCredential_G3/sqlite failed in the merge queue on it (run
// 40142034894). On a file (WAL, the production shape) the same load never fails.
func TestFactoryReplicas_SharedCacheLocksAndFileDoesNot(t *testing.T) {
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

	t.Run("shared-cache DSN: writes fail with database table is locked", func(t *testing.T) {
		_, locked, first := run(t, sqlitetest.DSN("replicas_lock_probe_"))
		require.Positive(t, locked, "control: two factory storages on a shared cache must collide, or the file half below proves nothing")
		require.Contains(t, first, "database table is locked (262)", "the shared-cache code CI failed on")
	})
	t.Run("file (FactoryPath): no write fails", func(t *testing.T) {
		writes, locked, _ := run(t, sqlitetest.FactoryPath(t, "replicas_lock_probe"))
		require.Zero(t, locked)
		require.Positive(t, writes)
	})
}
