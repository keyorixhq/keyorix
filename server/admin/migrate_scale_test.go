// migrate_scale_test.go (MIGRATE-SCALE-NOV-1, #3462): moving a seeded database
// between backends with `admin backup` + `admin restore`, in process, and
// checking what a pilot customer relies on:
//
//   - every content table has the same row count on the far side;
//   - `verify-audit` accepts the chain on the target (no new genesis);
//   - every secret version decrypts, with the key files the restore installed,
//     to the value that was written;
//   - the peak Go heap of the backup leg and of the restore leg does not grow
//     with the table sizes: each leg runs at multiplier 1 and 4 of the seeded
//     size and the larger run fails if its peak growth is out of proportion to
//     the smaller one. A loader that read a whole table into memory would grow
//     with the row count and trip this; noise would not.
//
// There is no separate "migrate" tool: moving between backends is backup on one
// and restore into an EMPTY database of the other (docs/SELF_HOSTING.md), so
// this is the migrator. The loader's batch size is pinned separately by
// internal/backupfmt TestLoadArchive_InsertsInBoundedBatches.
//
// Peak memory here is runtime.MemStats.HeapAlloc sampled while the leg runs.
// It does not see memory the SQLite or PostgreSQL driver allocates outside the Go
// heap, and the real-binary peak RSS of the same legs is what
// scripts/migrate/scale-check.sh measures. The two answer the same question from
// different sides.
//
// The PostgreSQL legs need KEYORIX_TEST_PG_DSN (kpg dsn <name>) and skip without
// it. Sizes: KEYORIX_MIGSCALE_* (migrate_scale_seed_test.go).
//
// Not t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

const (
	scaleBackendSQLite   = "sqlite"
	scaleBackendPostgres = "postgres"
	// scaleHeapSlackBytes is the headroom of the memory assertion: noise from
	// buffers, drivers and garbage not yet collected is not growth.
	scaleHeapSlackBytes = 64 << 20
)

// scaleEnd is one side of a move: a directory holding the config and key files
// and the database the config points at.
type scaleEnd struct {
	kind    string
	dir     string
	cfgPath string
	cfg     *config.Config
	dsn     string // PostgreSQL only
}

// newScaleEnd writes the config of one side. pgBase is the server's base DSN;
// a PostgreSQL side gets its own empty, uniquely named database.
func newScaleEnd(t *testing.T, kind, pgBase string) *scaleEnd {
	t.Helper()
	e := &scaleEnd{kind: kind, dir: t.TempDir()}
	chdirTest(t, e.dir)
	switch kind {
	case scaleBackendSQLite:
		e.cfgPath = writeBackupRestoreTestConfig(t, e.dir, filepath.Join(e.dir, "secrets.db"))
	case scaleBackendPostgres:
		e.dsn = pgAdminIsolatedDatabaseDSN(t, pgBase)
		e.cfgPath = writePostgresBackupRestoreTestConfig(t, e.dir, e.dsn)
	default:
		t.Fatalf("unknown backend %q", kind)
	}
	configPathFlag = e.cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	e.cfg = cfg
	return e
}

// enter makes e the current directory and the --config of the admin commands.
func (e *scaleEnd) enter(t *testing.T) {
	t.Helper()
	chdirTest(t, e.dir)
	configPathFlag = e.cfgPath
}

// openDB opens a gorm handle on e's database; the caller closes it.
func (e *scaleEnd) openDB(t *testing.T) *gorm.DB {
	t.Helper()
	if e.kind == scaleBackendPostgres {
		return pgAdminRawOpen(t, e.dsn)
	}
	db, err := storage.OpenGormDB(e.cfg)
	require.NoError(t, err)
	return db
}

// newScaleSource builds an initialised, migrated, seeded instance: key files,
// schema, then spec's rows.
func newScaleSource(t *testing.T, kind, pgBase string, spec scaleSpec) *scaleEnd {
	t.Helper()
	e := newScaleEnd(t, kind, pgBase)
	svc := encryption.NewService(&e.cfg.Storage.Encryption, e.dir)
	require.NoError(t, svc.Initialize(scaleSeedPassphrase))
	st, err := storage.NewStorageFactory().CreateStorage(e.cfg) // creates + migrates
	require.NoError(t, err)
	t.Cleanup(func() { closeTestStorage(st) })
	db := e.openDB(t)
	seedScale(t, db, svc, spec)
	if kind == scaleBackendSQLite {
		closeGormDB(db)
	}
	return e
}

// heapPeak samples HeapAlloc while a leg runs and reports the highest value
// above the heap that was live when it started.
type heapPeak struct {
	base uint64
	stop chan struct{}
	done chan uint64
}

func startHeapPeak() *heapPeak {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	h := &heapPeak{base: ms.HeapAlloc, stop: make(chan struct{}), done: make(chan uint64)}
	go func() {
		peak := h.base
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-h.stop:
				runtime.ReadMemStats(&ms)
				h.done <- max(peak, ms.HeapAlloc)
				return
			case <-tick.C:
				runtime.ReadMemStats(&ms)
				peak = max(peak, ms.HeapAlloc)
			}
		}
	}()
	return h
}

// finish stops sampling and returns the peak growth in bytes.
func (h *heapPeak) finish() uint64 {
	close(h.stop)
	peak := <-h.done
	if peak < h.base {
		return 0
	}
	return peak - h.base
}

// scaleMove is what one backup + restore of a seeded instance measured.
type scaleMove struct {
	spec                        scaleSpec
	backupGrowth, restoreGrowth uint64
	archiveBytes                int64
	secretVersions, auditEvents int64
}

// runScaleMove seeds a source of kind `from` at the given multiplier, moves it
// into an empty `to` and checks the far side. It returns the memory growth of
// both legs.
func runScaleMove(t *testing.T, from, to, pgBase string, mult int) scaleMove {
	t.Helper()
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", scaleSeedPassphrase)

	spec := scaleSpecFromEnv(t, mult)
	src := newScaleSource(t, from, pgBase, spec)

	// --- backup leg
	src.enter(t)
	archive := filepath.Join(t.TempDir(), "scale-backup.tar.gz")
	backupOutput = archive
	backupExclusive = false
	hp := startHeapPeak()
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	backupGrowth := hp.finish()
	require.NoError(t, err, "backup output:\n%s", out)
	info, err := os.Stat(archive)
	require.NoError(t, err)

	srcDB := src.openDB(t)
	srcCounts := scaleCounts(t, srcDB)
	if from == scaleBackendSQLite {
		closeGormDB(srcDB)
	}

	// --- restore leg into an empty database of the other backend
	dst := newScaleEnd(t, to, pgBase)
	dst.enter(t)
	restoreInput = archive
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	hp = startHeapPeak()
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	restoreGrowth := hp.finish()
	require.NoError(t, err, "restore output:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID",
		"restore must run verify-audit on the target and report its verdict")

	// --- the far side
	dstDB := dst.openDB(t)
	require.Equal(t, srcCounts, scaleCounts(t, dstDB), "every content table must have the source's row count")

	svc := encryption.NewService(&dst.cfg.Storage.Encryption, dst.dir)
	require.NoError(t, svc.Initialize(scaleSeedPassphrase), "the restored key files must unwrap with the source passphrase")
	versions := decryptAllScale(t, dstDB, svc)
	require.EqualValues(t, spec.Secrets*spec.Versions, versions, "decrypt-all must cover every seeded version")
	if to == scaleBackendSQLite {
		closeGormDB(dstDB)
	}
	verifyAuditValid(t, dst.cfgPath, int64(spec.Audit))

	return scaleMove{spec: spec, backupGrowth: backupGrowth, restoreGrowth: restoreGrowth, archiveBytes: info.Size(),
		secretVersions: versions, auditEvents: srcCounts["audit_events"]}
}

// requireBoundedGrowth fails when the larger run's peak heap growth is out of
// proportion to the smaller run's: more than twice, and more than the slack
// above it. The row counts of the two runs differ by `ratio`, so a leg that
// held a table in memory would grow by about that factor.
func requireBoundedGrowth(t *testing.T, leg string, small, big scaleMove, smallGrowth, bigGrowth uint64) {
	t.Helper()
	ratio := float64(big.auditEvents) / float64(small.auditEvents)
	t.Logf("%s: rows x%.1f, archive %d -> %d bytes, peak heap growth %d -> %d bytes",
		leg, ratio, small.archiveBytes, big.archiveBytes, smallGrowth, bigGrowth)
	require.GreaterOrEqual(t, ratio, 2.0, "the two runs must differ in size for the assertion to mean anything")
	limit := max(2*smallGrowth, smallGrowth+scaleHeapSlackBytes)
	require.LessOrEqual(t, bigGrowth, limit,
		"%s: peak heap growth rose from %d to %d bytes for %.1fx the rows (limit %d): a table is being held in memory",
		leg, smallGrowth, bigGrowth, ratio, limit)
}

// moveAtTwoSizes runs one direction at multiplier 1 and 4 and asserts both legs'
// memory stays bounded.
func moveAtTwoSizes(t *testing.T, from, to string) {
	t.Helper()
	base := ""
	if from == scaleBackendPostgres || to == scaleBackendPostgres {
		base = pgAdminTestDSN(t)
	}
	small := runScaleMove(t, from, to, base, 1)
	big := runScaleMove(t, from, to, base, 4)
	requireBoundedGrowth(t, "backup "+from, small, big, small.backupGrowth, big.backupGrowth)
	requireBoundedGrowth(t, "restore into "+to, small, big, small.restoreGrowth, big.restoreGrowth)
}

// TestMigrateScale_SQLiteToPostgres is the pilot customer's move: a SQLite
// instance with secrets, versions, users, roles, shares and an audit chain into an
// empty PostgreSQL database.
func TestMigrateScale_SQLiteToPostgres(t *testing.T) {
	moveAtTwoSizes(t, scaleBackendSQLite, scaleBackendPostgres)
}
