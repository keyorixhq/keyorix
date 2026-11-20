package storage

// factory_sqlite_read_audit_test.go — ADR-112 Amendment 7: on SQLite at
// audit_durability standard, only batches of successful secret-value read
// audits commit on the dedicated synchronous=NORMAL connection; everything
// else stays on the FULL pool, and the chain verifies across both.

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// readAuditTestStorage opens a file-backed SQLite store through the production
// factory at the given audit_durability ("" = the default).
func readAuditTestStorage(t *testing.T, level string) *store.LocalStorage {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg := &config.Config{}
	cfg.Storage.Type = "sqlite"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "read-audit.db")
	cfg.Storage.Database.AuditDurability = level
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "CreateStorage returned %T", st)
	t.Cleanup(func() { _ = ls.Close() })
	return ls
}

// batchCommit is one flusher transaction as auditBatchTxHook saw it.
type batchCommit struct {
	normal      bool
	synchronous int
}

// recordAuditBatchCommits installs the store's batch hook and records, for
// every flusher commit, which handle it ran on and the PRAGMA synchronous of
// the connection inside that very transaction.
func recordAuditBatchCommits(t *testing.T) func() []batchCommit {
	t.Helper()
	var mu sync.Mutex
	var seen []batchCommit
	restore := store.SetAuditBatchTxHookForTest(func(tx *gorm.DB, normal bool) {
		var pragma int
		if err := tx.Raw("PRAGMA synchronous").Scan(&pragma).Error; err != nil {
			pragma = -1
		}
		mu.Lock()
		seen = append(seen, batchCommit{normal: normal, synchronous: pragma})
		mu.Unlock()
	})
	t.Cleanup(restore)
	return func() []batchCommit {
		mu.Lock()
		defer mu.Unlock()
		return append([]batchCommit(nil), seen...)
	}
}

func readAuditEvent(eventType string, success bool, i int) *models.AuditEvent {
	return &models.AuditEvent{
		EventType:   eventType,
		Success:     &success,
		Description: fmt.Sprintf("%s #%d", eventType, i),
		EventTime:   time.Now(),
	}
}

func requireChainValid(t *testing.T, ls *store.LocalStorage, wantRows int64) {
	t.Helper()
	res, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Valid, "audit chain must verify: %+v", res)
	var n int64
	require.NoError(t, ls.DB().Model(&models.AuditEvent{}).Count(&n).Error)
	require.Equal(t, wantRows, n)
}

// TestSQLiteReadAuditConn_PragmaPerConnection: at standard, every connection of
// the shared pool reports FULL (2) and a read-audit batch commits on a
// connection reporting NORMAL (1); at strict (the default) no batch ever
// commits on anything but FULL.
func TestSQLiteReadAuditConn_PragmaPerConnection(t *testing.T) {
	ctx := context.Background()
	t.Run("standard", func(t *testing.T) {
		ls := readAuditTestStorage(t, "standard")
		sqlDB, err := ls.DB().DB()
		require.NoError(t, err)
		maxOpen := sqlDB.Stats().MaxOpenConnections
		require.Positive(t, maxOpen)
		// Hold every connection of the shared pool at once, so each one is a
		// distinct physical connection, and read the pragma on each.
		conns := make([]interface{ Close() error }, 0, maxOpen)
		for i := range maxOpen {
			c, err := sqlDB.Conn(ctx)
			require.NoError(t, err)
			conns = append(conns, c)
			var pragma int
			require.NoError(t, c.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&pragma))
			require.Equal(t, sqliteSynchronousFull, pragma, "shared pool connection %d must stay FULL at standard", i)
		}
		for _, c := range conns {
			require.NoError(t, c.Close())
		}

		seen := recordAuditBatchCommits(t)
		require.NoError(t, ls.LogAuditEvent(ctx, readAuditEvent("secret.read", true, 0)))
		got := seen()
		require.Equal(t, []batchCommit{{normal: true, synchronous: sqliteSynchronousNormal}}, got,
			"a successful read audit must commit on the dedicated NORMAL connection")
		requireChainValid(t, ls, 1)
	})
	t.Run("strict default", func(t *testing.T) {
		for _, level := range []string{"", "strict"} {
			ls := readAuditTestStorage(t, level)
			seen := recordAuditBatchCommits(t)
			require.NoError(t, ls.LogAuditEvent(ctx, readAuditEvent("secret.read", true, 0)))
			require.Equal(t, []batchCommit{{normal: false, synchronous: sqliteSynchronousFull}}, seen(),
				"audit_durability %q: there is no NORMAL connection, the read audit commits FULL", level)
		}
	})
}

// TestSQLiteReadAuditConn_OnlyReadBatchesUseNormal: one event at a time (each
// LogAuditEvent waits for its own batch), only successful secret.read and
// connect.secret_read go to NORMAL. A mutation's audit row, a denied read and
// a metadata read commit FULL, and so does a read audit written inside a
// caller's transaction, and that transaction itself (the direct path, no
// flusher). Mixed batches are covered by store's
// TestIsSQLiteNormalReadAuditBatch.
func TestSQLiteReadAuditConn_OnlyReadBatchesUseNormal(t *testing.T) {
	ctx := context.Background()
	ls := readAuditTestStorage(t, "standard")
	seen := recordAuditBatchCommits(t)

	cases := []struct {
		eventType string
		success   bool
		normal    bool
	}{
		{"secret.read", true, true},
		{"connect.secret_read", true, true},
		{"secret.read", false, false},         // a denied read stays FULL
		{"connect.secret_read", false, false}, // a refused federated read
		{"secret.updated", true, false},       // a mutation's audit row
		{"secret.created", true, false},
		{"secret.deleted", true, false},
		{"secret.metadata_read", true, false},
		{"role.assigned", true, false},
	}
	for i, tc := range cases {
		require.NoError(t, ls.LogAuditEvent(ctx, readAuditEvent(tc.eventType, tc.success, i)))
		got := seen()
		require.Len(t, got, i+1)
		want := batchCommit{normal: tc.normal, synchronous: sqliteSynchronousFull}
		if tc.normal {
			want.synchronous = sqliteSynchronousNormal
		}
		require.Equal(t, want, got[i], "%s success=%v", tc.eventType, tc.success)
	}

	// A mutation transaction, with a read audit appended inside it: the whole
	// transaction is on the shared pool and reports FULL, and the flusher's
	// hook never sees it (the clone's append is the direct path).
	before := len(seen())
	require.NoError(t, ls.WithTransaction(ctx, func(tx corestorage.Storage) error {
		txs, ok := tx.(*store.LocalStorage)
		require.True(t, ok)
		var pragma int
		if err := txs.DB().Raw("PRAGMA synchronous").Scan(&pragma).Error; err != nil {
			return err
		}
		require.Equal(t, sqliteSynchronousFull, pragma, "a mutation transaction must run on a FULL connection")
		return tx.LogAuditEvent(ctx, readAuditEvent("secret.read", true, 100))
	}))
	require.Len(t, seen(), before, "an append inside a caller's transaction must not go through the flusher")

	requireChainValid(t, ls, int64(len(cases)+1))
}

// TestSQLiteReadAuditConn_InterleavedChainVerifies: read audits (NORMAL) and
// mutation audit rows plus non-audit mutations (FULL) from concurrent
// goroutines. Each batch reads the head inside its own write transaction, on
// whichever handle commits it, so the chain links across the two handles: it
// verifies and holds every row. The test fails unless both handles really
// committed batches, so it cannot pass by accident on one handle.
func TestSQLiteReadAuditConn_InterleavedChainVerifies(t *testing.T) {
	ctx := context.Background()
	ls := readAuditTestStorage(t, "standard")
	seen := recordAuditBatchCommits(t)

	require.NoError(t, ls.DB().Exec("CREATE TABLE interleave_probe (k TEXT PRIMARY KEY, v TEXT)").Error)

	const readers, writers, perWorker = 6, 3, 40
	var wg sync.WaitGroup
	errs := make(chan error, (readers+writers)*perWorker*2)
	for r := range readers {
		wg.Go(func() {
			for i := range perWorker {
				errs <- ls.LogAuditEvent(ctx, readAuditEvent("secret.read", true, r*1000+i))
			}
		})
	}
	for w := range writers {
		wg.Go(func() {
			for i := range perWorker {
				// A non-audit write on the FULL pool, then its audit row.
				errs <- ls.DB().WithContext(ctx).Exec(
					"INSERT INTO interleave_probe (k, v) VALUES (?, ?)",
					fmt.Sprintf("interleave-%d-%d", w, i), "v").Error
				errs <- ls.LogAuditEvent(ctx, readAuditEvent("secret.updated", true, w*1000+i))
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	var normal, full int
	for _, c := range seen() {
		if c.normal {
			require.Equal(t, sqliteSynchronousNormal, c.synchronous)
			normal++
		} else {
			require.Equal(t, sqliteSynchronousFull, c.synchronous)
			full++
		}
	}
	require.Positive(t, normal, "no batch committed on the NORMAL connection: the interleaving was not exercised")
	require.Positive(t, full, "no batch committed on the FULL pool: the interleaving was not exercised")
	requireChainValid(t, ls, int64((readers+writers)*perWorker))
}
