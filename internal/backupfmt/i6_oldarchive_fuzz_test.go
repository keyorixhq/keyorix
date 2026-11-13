package backupfmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// FuzzI6OldArchiveMutation fuzzes the RESTORE-side fail-closed guarantees of a
// v2 logical backup archive that was produced by a REAL older released binary
// (v0.96.3, built from the git tag), not a synthetic archive assembled from
// current main's models. The seed under testdata/i6/ is byte-for-byte what that
// old binary's `admin backup` wrote.
//
// The existing synthetic-archive fuzzers (TestArchiveBitFlip via verifierflip,
// FuzzCheckSchemaDelta, FuzzLoadArchiveIgnoresManifestTableOrder,
// reader_fuzz_test.go, manifest_sign_fuzz_test.go) all build their artifact from
// the CURRENT compiled-in models; none of them starts from what an old release
// actually emitted. This target does, and drives the full extract+load path.
//
// Property (fail-closed + no partial state + no silent content change). For any
// mutation b of the real old archive:
//   - ExtractArchive(b) either REFUSES (any gzip/tar damage, any per-entry
//     sha256 mismatch, any structural violation -- the common case), in which
//     case nothing was loaded and there is nothing further to check; OR
//   - it accepts b as structurally intact and every staged entry's bytes match
//     the manifest's pinned digests, in which case LoadArchive into a fresh,
//     fully-migrated current-main database inside ONE transaction must either:
//   - fail, and leave the target completely empty (the transaction rolled
//     back -- no half-restored rows); OR
//   - succeed, and reproduce EXACTLY the baseline restored content (a
//     content digest over the load-bearing tables equals the pristine
//     archive's). A successful load that differs from baseline would mean a
//     mutation silently altered restored data despite passing extraction --
//     that is the regression this asserts against (e.g. if the per-entry
//     digest pin were ever removed from ExtractArchive).
//
// What this target does NOT verify:
//   - the HMAC manifest-signature gate (VerifyManifestSignature): deriving the
//     real archive's signing key needs the KEK-unwrap machinery that lives in
//     server/admin; the signature gate is fuzzed independently in
//     manifest_sign_fuzz_test.go. End to end, server/admin
//     TestI6RestoreOldVersion exercises only its ACCEPT path on the real
//     archive, and TestI6RestoreOldVersion_CorruptFailsClosed/manifest-tamper
//     its REFUSE path on one tampered manifest. This target isolates the
//     extract+load integrity layer.
//   - the "no key material written" property (dek.key/kek.salt): LoadArchive
//     never writes key files -- that happens only in the full admin command, so
//     it is asserted by server/admin TestI6RestoreOldVersion_CorruptFailsClosed.
//   - decryption of the restored secrets (content is compared as ciphertext
//     bytes here; plaintext decryption is TestI6RestoreOldVersion's job).
func FuzzI6OldArchiveMutation(f *testing.F) {
	seed := i6ReadSeedArchive(f)
	f.Add(seed)
	f.Add(seed[:len(seed)/2])                          // truncation
	f.Add(seed[:1])                                    // 1-byte
	f.Add([]byte{})                                    // empty
	f.Add(append(bytes.Clone(seed), 0x00, 0x01, 0x02)) // trailing bytes

	// One migrated target per worker PROCESS (Go fuzzing runs each -parallel
	// worker as its own process, executing inputs sequentially), reused across
	// every exec. LoadArchive always runs in a transaction we force to ROLL BACK
	// -- even on success, after digesting the loaded rows inside the txn -- so the
	// DB returns to empty between execs and the 80-table migration is paid once
	// per process, not once per input. The forced rollback is also the
	// no-partial-state oracle: LoadArchive must confine every write to its
	// transaction, which production (restore.go) relies on.
	db := i6MigratedDB(f)
	baselineDigest, baseOK := i6ExtractLoadRollback(f, db, seed)
	require.True(f, baseOK, "the pristine old-release archive must extract and load into current main")
	require.NotEmpty(f, baselineDigest)
	i6RequireEmpty(f, db) // the forced rollback left nothing behind

	f.Fuzz(func(t *testing.T, b []byte) {
		// Watchdog: with the 64 KiB / 2000-row harness caps above, a legitimate
		// extract+load is well under a second. A >20 s exec means a pathological
		// input slipped both caps and is worth triaging as a potential slow-restore
		// (DoS) shape -- fail so Go saves it to testdata/fuzz. 20 s (not 1-2 s)
		// tolerates ordinary scheduling jitter on this shared, sometimes-hot host.
		start := time.Now()
		digest, ok := i6ExtractLoadRollback(t, db, b)
		if el := time.Since(start); el > 20*time.Second {
			t.Fatalf("I6-SLOW-EXEC: extract+load took %s on a %d-byte input", el, len(b))
		}
		i6RequireEmpty(t, db) // after EVERY exit path: no partial state survived
		if !ok {
			return // fail-closed at extract or load
		}
		require.Equal(t, baselineDigest, digest,
			"a mutation extracted AND loaded successfully but produced DIFFERENT restored content "+
				"than the pristine archive -- a silent accept of altered backup content")
	})
}

// i6ExtractLoadRollback runs ExtractArchive then, on success, LoadArchive into
// db inside a transaction that is ALWAYS rolled back. It returns
// (contentDigest, true) only when BOTH extract and load succeed (the digest is
// computed inside the txn, before rollback). A refused extraction or a failed
// load returns ("", false); the caller asserts the DB is empty afterwards.
func i6ExtractLoadRollback(t testing.TB, db *gorm.DB, b []byte) (string, bool) {
	stagingDir, err := os.MkdirTemp("", "i6-oldarch-*")
	if err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()

	// Bounded limits (the real archive decompresses to ~30 KiB across 80 table
	// files). A mutation can both (a) inflate a gzip entry toward a decompression
	// bomb and (b) craft a compact NDJSON table file that expands to hundreds of
	// thousands of rows, each of which LoadArchive INSERTs -- both stall the
	// fuzzer for seconds and starve coverage. 64 KiB (~2x the real total) keeps
	// every legitimate mutation in range while refusing both amplification shapes
	// promptly. This is a HARNESS speed bound, not a product claim: the product's
	// caps are operator-set (restoreMaxEntryBytes/restoreMaxTotalBytes) and the
	// cap mechanism itself is fuzzed via reader_fuzz_test.go.
	const cap64KiB = 64 << 10
	manifest, err := ExtractArchive(bytes.NewReader(b), stagingDir, cap64KiB, cap64KiB)
	if err != nil {
		return "", false // extraction refused -- fail-closed, nothing loaded
	}

	// Harness row budget: a mutation can craft a compact NDJSON table file that
	// still extracts but declares tens of thousands of rows, each of which
	// LoadArchive INSERTs and i6ContentDigest then serialises -- seconds per exec,
	// which collapses fuzz throughput. The real fixture has 17 rows, so a 2000-row
	// ceiling never skips a legitimate mutation; above it we stop after the
	// (already-validated) extraction rather than pay the amplified load. Row-count
	// amplification of restore is an operator-cap concern, not this oracle's.
	var declaredRows int64
	for _, te := range manifest.Tables {
		declaredRows += te.RowCount
	}
	if declaredRows > 2000 {
		return "", false
	}

	var digest string
	var loaded bool
	errForceRollback := errors.New("i6: force rollback after a successful load")
	_ = db.Transaction(func(tx *gorm.DB) error {
		if lerr := LoadArchive(tx, manifest, stagingDir); lerr != nil {
			return lerr // real load failure -> rollback
		}
		digest = i6ContentDigest(t, tx) // digest inside the txn, before rollback
		loaded = true
		return errForceRollback // force rollback even though the load succeeded
	})
	return digest, loaded
}

// i6RequireEmpty asserts every load-bearing table is empty -- the no-partial-
// state invariant, checked after every exec since each one rolls back.
func i6RequireEmpty(t testing.TB, db *gorm.DB) {
	for _, table := range i6ContentTables {
		var n int64
		require.NoError(t, db.Table(table).Count(&n).Error)
		require.Zero(t, n, "no partial state: %q must be empty between execs (a LoadArchive write escaped its transaction)", table)
	}
}

// i6ContentTables are the load-bearing tables whose content the differential
// oracle digests and whose emptiness proves a clean rollback. They are the
// tables the fixture actually populates (see scripts/i6-gen expected.json).
var i6ContentTables = []string{
	"projects", "environments", "secret_nodes", "secret_versions",
	"users", "roles", "user_roles", "api_tokens", "machine_identities", "machine_identity_roles",
}

// i6ContentDigest is a deterministic digest over the load-bearing tables' row
// content, read as raw column maps ordered by id, so a single successful-load
// digest captures "exactly these rows, these bytes" without hard-coding a
// column list that would drift as models evolve.
func i6ContentDigest(t testing.TB, db *gorm.DB) string {
	h := sha256.New()
	for _, table := range i6ContentTables {
		var rows []map[string]any
		// No ORDER BY: some load-bearing tables are composite-key join tables
		// (user_roles, machine_identity_roles) with no "id" column. Serialize
		// each row to a canonical string (sorted keys) and sort those strings in
		// Go, so the digest is order-independent and column-list-agnostic.
		require.NoError(t, db.Table(table).Find(&rows).Error)
		rowStrs := make([]string, 0, len(rows))
		for _, row := range rows {
			keys := make([]string, 0, len(row))
			for k := range row {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var sb bytes.Buffer
			for _, k := range keys {
				sb.WriteString(k)
				sb.WriteByte('=')
				sb.Write(toBytes(row[k]))
				sb.WriteByte('\x1f')
			}
			rowStrs = append(rowStrs, sb.String())
		}
		sort.Strings(rowStrs)
		h.Write([]byte(table))
		for _, s := range rowStrs {
			h.Write([]byte(s))
			h.Write([]byte{'\x1e'})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func toBytes(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte("\x00nil")
	case []byte:
		return x
	case string:
		return []byte(x)
	default:
		return []byte(fmt.Sprintf("%v", x))
	}
}

// i6ReadSeedArchive reads the committed real old-release archive seed.
func i6ReadSeedArchive(t testing.TB) []byte {
	raw, err := os.ReadFile(filepath.Join("testdata", "i6", "v0.96.3-backup.tar.gz"))
	require.NoError(t, err)
	return raw
}

// i6MigratedDB creates a single fresh, full current-schema SQLite database via
// the real storage factory (creates + migrates all 80 tables) and returns an
// open gorm handle, closed on cleanup. One per worker process; reused across
// every exec via always-rollback transactions.
func i6MigratedDB(t testing.TB) *gorm.DB {
	dir, err := os.MkdirTemp("", "i6-db-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dbPath := filepath.Join(dir, "target.db")
	cfg := &config.Config{Storage: config.StorageConfig{
		Type:     "local",
		Database: config.DatabaseConfig{Path: dbPath},
	}}
	_, err = storage.NewStorageFactory().CreateStorage(cfg) // creates + migrates
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	// Pin to a SINGLE connection. The SQLite backend uses _txlock=immediate +
	// _busy_timeout=10000: with a multi-connection pool, this fuzzer's reused
	// always-rollback write transaction contends with the pool's other
	// connections and every contended op blocks the full 10 s busy timeout,
	// collapsing throughput to a handful of execs. One connection serializes all
	// work and removes the contention entirely (the same pattern several
	// internal/storage tests use).
	if sqlDB, dbErr := gdb.DB(); dbErr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	t.Cleanup(func() {
		if sqlDB, dbErr := gdb.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return gdb
}
