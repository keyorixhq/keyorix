// restore_commit.go is the commit half of `admin restore` (RESTORE-OVERWRITE-
// FIX-1): how the staged key files and data become live together, and how
// `admin restore --recover` resolves a restore that was killed in between.
//
// The order, on both backends:
//  1. Stage: every key file, and the key-set manifest recording them
//     (prepareRestoredKeySet), is written and fsynced next to its target as
//     <path>.restoring-<rand>; nothing live is touched. SQLite also builds
//     the whole restored database at <db>.restoring-<ts> and loads it there.
//  2. Journal: restorejournal.Write fsyncs every staged file's directory,
//     then records every staged file with its SHA-256.
//  3. Commit point. PostgreSQL: one transaction clears the target tables
//     (under --overwrite-existing), loads the archive, resyncs sequences and
//     writes the journal's token into system_metadata. SQLite: the journal
//     itself (it is written only once every staged file is complete).
//  4. Install: every entry is checked first (a staged file must still hash
//     to its recorded SHA-256; a missing one counts as installed only if the
//     live file does), then each staged file is renamed over its target, the
//     original moved aside to <path>.pre-restore-<ts>, and the journal is
//     rewritten as installed.
//  5. Finish: audit events, witness, journal removed. A crash inside this
//     step makes --recover write the audit events again (they precede the
//     journal's removal so that a crash can duplicate them but never lose
//     them).
//
// A failure before the commit point removes the staged files and the
// journal: the live keys and data are exactly what they were. A failure or
// crash after it leaves the journal, the server refuses to start
// (restorejournal.RefuseIfPresent), and --recover rolls the restore forward.
// A crash before it (PostgreSQL) leaves a journal whose token never reached
// the database, and --recover rolls back. A crash before step 2 leaves only
// staged files, which the next restore or --recover removes
// (removeOrphanStagedFiles). Recovery that cannot vouch for a staged file
// refuses and changes nothing.
package admin

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// restoreRecover is `admin restore --recover`.
var restoreRecover bool

// restoreStepHook is a test seam called at each step boundary of the commit
// sequence ("journal-written", "loaded", "committed", "installed-1", ...). A
// non-nil error aborts the restore at that point; kill-point tests exit the
// process from it.
var restoreStepHook = func(step string) error { return nil }

// restoreTokenMetadataKey is the system_metadata row the PostgreSQL load
// transaction writes the journal's token to.
const restoreTokenMetadataKey = "restore_commit_token"

// postgresRestoreKeptMetadataKeys are the system_metadata rows a cleared
// PostgreSQL target keeps: the schema epoch rows migration writes, which
// backupfmt.LoadArchive deliberately never loads from an archive (mirrors
// internal/storage's schemaEpochMetadataKey/schemaMinCompatibleEpochMetadataKey
// byte for byte, the same way internal/backupfmt does).
var postgresRestoreKeptMetadataKeys = []string{"schema_epoch", "schema_min_compatible_epoch"}

func newRestoreToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate restore token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// keySetManifestPath is where cfg's key-set manifest lives (#2900), "" when
// cfg configures no DEK path. Relative, like expectedKeyFilePaths.
func keySetManifestPath(cfg *config.Config) (string, error) {
	return keyfiles.ManifestPath(&cfg.Storage.Encryption, ".")
}

// prepareRestoredKeySet stages a restored key set: every key file
// (prepareRestoredFileSet) and, as one more entry of the same set, the
// key-set manifest that records them (keyfiles.SetWriter.PlanCommit: the
// restored hashes at the next generation, nothing staged). It is the only way
// restore stages key material, so a journal that installs key files always
// installs the manifest that matches them, in the same install step
// (installJournalEntries) and under the same roll-forward/roll-back decision.
// The manifest is not written through its own .pending/rename two-phase
// commit: the journal already is the commit protocol for this set, and a
// second one could disagree with it about whether the restore happened.
//
// The manifest entry comes after the key files, so while a killed install is
// unresolved the manifest still describes the replaced set and the boot-time
// manifest check refuses the half-installed one (if the journal were lost);
// with the journal present the server refuses earlier, naming --recover.
func prepareRestoredKeySet(cfg *config.Config, paths []string, data [][]byte) ([]restorejournal.Entry, error) {
	ks, err := keyfiles.NewSetWriter(&cfg.Storage.Encryption, ".")
	if err != nil {
		return nil, fmt.Errorf("key-set manifest: %w", err)
	}
	if ks == nil || len(paths) == 0 {
		return prepareRestoredFileSet(paths, data)
	}
	if len(paths) != len(data) {
		return nil, fmt.Errorf("internal error: %d paths but %d data buffer(s) for a restored key set", len(paths), len(data))
	}
	restored := make(map[string][]byte, len(paths))
	for i, p := range paths {
		restored[p] = data[i]
	}
	manifest, err := ks.PlanCommit(keyfiles.OpRestore, restored)
	if err != nil {
		return nil, fmt.Errorf("key-set manifest for the restored key files: %w", err)
	}
	return prepareRestoredFileSet(append(slices.Clone(paths), ks.Path()), append(slices.Clone(data), manifest))
}

// prepareRestoredFileSet stages every file of a set (prepareRestoredFile)
// without installing any; on error nothing is left behind. The entries carry
// absolute paths and each staged file's SHA-256.
func prepareRestoredFileSet(paths []string, data [][]byte) ([]restorejournal.Entry, error) {
	if len(paths) != len(data) {
		return nil, fmt.Errorf("internal error: %d paths but %d data buffer(s) for a restored file set", len(paths), len(data))
	}
	var entries []restorejournal.Entry
	for i, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			discardStagedEntries(entries)
			return nil, fmt.Errorf("resolve %q: %w", path, err)
		}
		tmpPath, err := prepareRestoredFile(abs, data[i])
		if err != nil {
			discardStagedEntries(entries)
			return nil, err
		}
		entries = append(entries, restorejournal.Entry{Path: abs, Staged: tmpPath, SHA256: restorejournal.HashBytes(data[i])})
	}
	return entries, nil
}

// removeOrphanStagedFiles removes what a restore killed before it wrote its
// journal leaves beside cfg's key files and database: <target>.restoring-*
// staged copies (archive key material, mode 0600, plus a staged SQLite
// database and its sidecars) and journal temp files. Only call it holding
// the database lock with no journal present; each removal is printed.
func removeOrphanStagedFiles(cfg *config.Config) error {
	targets, err := restoreKeySetTargets(cfg)
	if err != nil {
		return err
	}
	if !isPostgresStorage(cfg) {
		targets = append(targets, sqliteDBPath(cfg))
	}
	prefixes := map[string][]string{} // directory -> name prefixes
	for _, t := range targets {
		abs, err := filepath.Abs(t)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", t, err)
		}
		dir := filepath.Dir(abs)
		prefixes[dir] = append(prefixes[dir], filepath.Base(abs)+".restoring-")
	}
	if jdir, err := restorejournal.Dir(cfg); err == nil && jdir != "" {
		prefixes[jdir] = append(prefixes[jdir], restorejournal.FileName+".tmp-")
	}
	for dir, pfx := range prefixes {
		names, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("list %q for leftover restore files: %w", dir, err)
		}
		for _, de := range names {
			if !de.Type().IsRegular() || !slices.ContainsFunc(pfx, func(p string) bool { return strings.HasPrefix(de.Name(), p) }) {
				continue
			}
			p := filepath.Join(dir, de.Name())
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("remove leftover restore file %q: %w", p, err)
			}
			fmt.Printf("Removed a leftover staged file from an earlier interrupted restore (it never became live): %s\n", p)
		}
	}
	return nil
}

// restoreKeySetTargets is every file a restore's key set installs:
// expectedKeyFilePaths plus the key-set manifest (prepareRestoredKeySet).
func restoreKeySetTargets(cfg *config.Config) ([]string, error) {
	paths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return nil, err
	}
	manifest, err := keySetManifestPath(cfg)
	if err != nil {
		return nil, fmt.Errorf("key-set manifest: %w", err)
	}
	if manifest != "" && len(paths) > 0 {
		paths = append(paths, manifest)
	}
	return paths, nil
}

// discardStagedEntries removes staged files that were never installed.
func discardStagedEntries(entries []restorejournal.Entry) {
	for _, e := range entries {
		_ = os.Remove(e.Staged)
		if e.SQLiteDB {
			_ = removeStagedSQLiteSidecars(e.Staged)
		}
	}
}

// installJournalEntries installs every staged file of j, then rewrites the
// journal at journalPath as installed. Idempotent, so a recovery can run it
// again after a crash part-way through. Every entry is checked before the
// first rename (checkJournalEntries): an entry that cannot be vouched for
// stops the install with nothing renamed.
func installJournalEntries(journalPath string, j *restorejournal.Journal) error {
	if j.Installed {
		return nil
	}
	if err := checkJournalEntries(j.Entries); err != nil {
		return err
	}
	for i, e := range j.Entries {
		if err := installJournalEntry(e, j.Timestamp, j.Overwrite); err != nil {
			return fmt.Errorf("install %q: %w", e.Path, err)
		}
		if err := restoreStepHook(fmt.Sprintf("installed-%d", i+1)); err != nil {
			return err
		}
	}
	j.Installed = true
	if err := restorejournal.Write(journalPath, *j); err != nil {
		return fmt.Errorf("record the install in the restore journal: %w", err)
	}
	return nil
}

// errUnvouchedStagedFile marks a journal entry recovery cannot vouch for.
var errUnvouchedStagedFile = errors.New("recovery refuses to install it")

// checkJournalEntries verifies, before anything is renamed, that every entry
// is either still staged with the content the restore staged, or already
// installed (the live file has that content). Anything else -- a staged file
// lost to a crash (its directory entry never reached the disk) beside a live
// file that is not the restored one, or a staged file whose content changed
// -- is refused: rolling forward would pair the restored data with key files
// from another point in time.
func checkJournalEntries(entries []restorejournal.Entry) error {
	for _, e := range entries {
		got, err := restorejournal.HashFile(e.Staged)
		if err == nil {
			if got != e.SHA256 {
				return fmt.Errorf("staged file %q does not have the content the restore staged for %q (SHA-256 %s, journal "+
					"records %s): %w", e.Staged, e.Path, got, e.SHA256, errUnvouchedStagedFile)
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read staged file %q: %w", e.Staged, err)
		}
		live, lerr := restorejournal.HashFile(e.Path)
		if lerr == nil && live == e.SHA256 {
			continue // installed by an earlier run
		}
		return fmt.Errorf("staged file %q is missing and %q is not the restored file (a crash lost the staged copy "+
			"before it was installed): %w", e.Staged, e.Path, errUnvouchedStagedFile)
	}
	return nil
}

func installJournalEntry(e restorejournal.Entry, ts string, overwrite bool) error {
	staged, err := os.Lstat(e.Staged)
	if errors.Is(err, os.ErrNotExist) {
		return nil // installed by an earlier run (checkJournalEntries saw the live file match)
	}
	if err != nil {
		return fmt.Errorf("stat staged file %q: %w", e.Staged, err)
	}
	// Without --overwrite-existing the staged file is hard-linked into place;
	// a crash after the link but before the staged name was removed leaves
	// both names on one file.
	if live, err := os.Lstat(e.Path); err == nil && os.SameFile(live, staged) {
		if err := os.Remove(e.Staged); err != nil {
			return err
		}
		return fsyncDir(filepath.Dir(e.Path))
	}
	if e.SQLiteDB {
		if err := moveAsideSQLiteDB(e.Path, ts, overwrite); err != nil {
			return err
		}
	}
	return commitRestoredFile(e.Path, e.Staged, ts, overwrite)
}

// moveAsideSQLiteDB clears the way for a restored SQLite database at dbPath.
// With overwrite, the live database and its -wal/-shm sidecars (which hold
// committed pages of THAT database) are renamed to <path>.pre-restore-<ts>,
// sidecars first, so no crash point leaves an old WAL next to the new file.
// Without it the target is missing or a 0-byte placeholder
// (refuseNonEmptyExisting), and only stale sidecars are removed.
func moveAsideSQLiteDB(dbPath, ts string, overwrite bool) error {
	if !overwrite {
		return removeStaleSQLiteSidecars(dbPath)
	}
	for _, suffix := range []string{"-wal", "-shm", ""} {
		src := dbPath + suffix
		aside := fmt.Sprintf("%s.pre-restore-%s%s", dbPath, ts, suffix)
		if err := os.Rename(src, aside); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("move existing %q aside to %q: %w", src, aside, err)
		}
	}
	return fsyncDir(filepath.Dir(dbPath))
}

// finishRestore runs the steps after the install: the audit events the
// restore owes, the rollback-protection witness, the encryption of any
// plaintext credential column an older archive carried, then the journal's
// removal.
func finishRestore(cfg *config.Config, journalPath string, j restorejournal.Journal) error {
	recordAdminAction(cfg, "admin.restore_completed", j.CompletedEvent, true)
	if j.WitnessValue != "" {
		if _, werr := auditverify.WriteWitnessIfHigher(j.WitnessPath, j.WitnessValue); werr != nil {
			fmt.Printf("note: could not update the rollback-protection witness file: %v\n", werr)
		}
	}
	if j.RollbackOverrideEvent != "" {
		recordAdminAction(cfg, "admin.restore_rollback_override", j.RollbackOverrideEvent, true)
	}
	// Before the journal goes: a failure here keeps it, so the server stays
	// refused and --recover retries the encryption instead of the restore
	// reporting a half-finished success.
	if err := encryptRestoredNotificationURLs(cfg); err != nil {
		return fmt.Errorf("the restored data is committed, but encrypting the notification channel URLs it carried "+
			"failed (%w) -- the journal %s is kept and the server refuses to start; fix the cause and run "+
			"`keyorix-server admin restore --recover`", err, journalPath)
	}
	if err := restoreStepHook("finishing"); err != nil {
		return err
	}
	if err := restorejournal.Remove(journalPath); err != nil {
		return fmt.Errorf("the restore is complete, but its journal could not be removed (%w) -- the server refuses "+
			"to start while it exists; run `keyorix-server admin restore --recover`", err)
	}
	if j.Token != "" {
		if err := deletePostgresRestoreToken(cfg); err != nil {
			fmt.Printf("note: could not remove the %s row (harmless): %v\n", restoreTokenMetadataKey, err)
		}
	}
	return nil
}

// restoreInterruptedError is what a failure after the commit point returns.
func restoreInterruptedError(journalPath string, err error) error {
	return fmt.Errorf("%w -- the restored data is committed but not every key file is installed; the journal %s is "+
		"kept and the server refuses to start until `keyorix-server admin restore --recover` completes the restore", err, journalPath)
}

// clearPostgresRestoreTarget empties every table the model registry defines,
// inside the load transaction, so an --overwrite-existing restore loads into
// the same state a freshly migrated database has. TRUNCATE is transactional
// on PostgreSQL: a failed load rolls the rows back with it.
func clearPostgresRestoreTarget(tx *gorm.DB) error {
	var tables []string
	for _, m := range storage.AllModels() {
		s, err := schema.Parse(m, &postgresResyncSchemaCache, schema.NamingStrategy{})
		if err != nil {
			return fmt.Errorf("parse schema for %T: %w", m, err)
		}
		if s.Table == "system_metadata" {
			continue
		}
		tables = append(tables, quoteIdentPG(s.Table))
	}
	// #nosec G202 -- every name is a registry model's GORM table name, quoted by quoteIdentPG
	if err := tx.Exec("TRUNCATE TABLE " + strings.Join(tables, ", ")).Error; err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table names come from storage.AllModels(), never from archive or request content
		return fmt.Errorf("clear target tables: %w", err)
	}
	if err := tx.Exec("DELETE FROM system_metadata WHERE key NOT IN ?", postgresRestoreKeptMetadataKeys).Error; err != nil {
		return fmt.Errorf("clear target system_metadata: %w", err)
	}
	return nil
}

func writePostgresRestoreToken(tx *gorm.DB, token string) error {
	return tx.Exec("INSERT INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?) "+
		"ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
		restoreTokenMetadataKey, token, time.Now().UTC()).Error
}

// postgresRestoreTokenCommitted reports whether the load transaction carrying
// token committed. An error means the outcome is unknown.
func postgresRestoreTokenCommitted(cfg *config.Config, token string) (bool, error) {
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return false, err
	}
	defer db.Close() //nolint:errcheck
	var got string
	err = db.QueryRow("SELECT value FROM system_metadata WHERE key = $1", restoreTokenMetadataKey).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		if isPostgresUndefinedTable(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", restoreTokenMetadataKey, err)
	}
	return got == token, nil
}

func deletePostgresRestoreToken(cfg *config.Config) error {
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	_, err = db.Exec("DELETE FROM system_metadata WHERE key = $1", restoreTokenMetadataKey)
	return err
}

// runAdminRestoreRecover is `admin restore --recover`.
func runAdminRestoreRecover(cfg *config.Config) error {
	journalPath, err := restorejournal.Path(cfg)
	if err != nil {
		return err
	}
	if journalPath == "" {
		fmt.Println("No interrupted restore to recover: this config has no restore journal location.")
		return nil
	}
	j, found, err := restorejournal.Read(journalPath)
	if err != nil {
		return fmt.Errorf("%w -- recovery refuses to guess; inspect the file", err)
	}
	if !found {
		if !forceFlag {
			if err := removeOrphanStagedFiles(cfg); err != nil {
				return err
			}
		}
		fmt.Printf("No interrupted restore found (no %s). Nothing to do.\n", journalPath)
		return nil
	}
	fmt.Printf("Found the journal of an interrupted restore (%s backend, started %s): %s\n", j.Backend, j.Timestamp, journalPath)
	if err := validateJournalEntries(cfg, j); err != nil {
		return fmt.Errorf("%w -- recovery refuses to act on it; inspect the journal", err)
	}

	forward := true
	if j.Backend == "postgres" {
		forward, err = postgresRestoreTokenCommitted(cfg, j.Token)
		if err != nil {
			return fmt.Errorf("cannot tell whether the interrupted restore's data was committed (%w) -- nothing was "+
				"changed; fix the database connection and run --recover again", err)
		}
	}
	if !forward {
		discardStagedEntries(j.Entries)
		if err := restorejournal.Remove(journalPath); err != nil {
			return err
		}
		fmt.Println("Rolled back: the restore's data was never committed. The key files and the database are unchanged " +
			"from before the restore; its staged files were removed.")
		recordAdminAction(cfg, "admin.restore_recovered",
			fmt.Sprintf("rolled back an interrupted restore started %s (its data was never committed)", j.Timestamp), true)
		return nil
	}

	if err := installJournalEntries(journalPath, &j); err != nil {
		if errors.Is(err, errUnvouchedStagedFile) {
			return fmt.Errorf("%w -- recovery refuses to roll forward and changed nothing; the journal %s is kept and the "+
				"server keeps refusing to start. See docs/operator/restore-failure-modes.md (\"Recovery refuses\")", err, journalPath)
		}
		return restoreInterruptedError(journalPath, err)
	}
	if err := finishRestore(cfg, journalPath, j); err != nil {
		return err
	}
	fmt.Println("Rolled forward: the restore's data was committed; its key files are now installed (originals kept as *.pre-restore-" + j.Timestamp + ").")
	recordAdminAction(cfg, "admin.restore_recovered",
		fmt.Sprintf("completed an interrupted restore started %s (its data had been committed)", j.Timestamp), true)
	if j.Backend == "postgres" {
		return verifyRestoredAuditPostgres(cfg)
	}
	return verifyRestoredAudit(cfg, sqliteDBPath(cfg))
}

// validateJournalEntries checks a journal read from disk against cfg before
// recovery renames anything: the backend must be cfg's, every target must be
// one of cfg's own key files (or their key-set manifest) or its SQLite
// database, and every staged file
// must be a restore staging name in its target's directory. A journal is a
// file anyone with write access to that directory could plant; recovery must
// not become a way to rename arbitrary files over arbitrary paths, or to
// write the rollback-protection witness anywhere but this deployment's own
// witness file. Paths are compared absolute: run from another working
// directory, relative key paths name other files, and the journal is refused.
func validateJournalEntries(cfg *config.Config, j restorejournal.Journal) error {
	wantBackend := "sqlite"
	identityPath := sqliteDBPath(cfg)
	if isPostgresStorage(cfg) {
		wantBackend = "postgres"
		var err error
		if identityPath, err = postgresTargetIdentityPath(cfg); err != nil {
			return err
		}
	}
	if j.Backend != wantBackend {
		return fmt.Errorf("restore journal is for backend %q, this config is %q", j.Backend, wantBackend)
	}
	paths, err := restoreKeySetTargets(cfg)
	if err != nil {
		return err
	}
	dbPath, err := filepath.Abs(sqliteDBPath(cfg))
	if err != nil {
		return err
	}
	if wantBackend == "sqlite" {
		paths = append(paths, dbPath)
	}
	allowed := make([]string, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		allowed = append(allowed, abs)
	}
	for _, e := range j.Entries {
		if !slices.Contains(allowed, e.Path) {
			return fmt.Errorf("restore journal names %q, which is not one of this config's key files or database "+
				"(relative paths resolve against the working directory: run --recover from the directory the restore ran in)", e.Path)
		}
		if e.SQLiteDB != (wantBackend == "sqlite" && e.Path == dbPath) {
			return fmt.Errorf("restore journal marks %q inconsistently as the SQLite database", e.Path)
		}
		if filepath.Dir(e.Staged) != filepath.Dir(e.Path) ||
			!strings.HasPrefix(filepath.Base(e.Staged), filepath.Base(e.Path)+".restoring-") {
			return fmt.Errorf("restore journal's staged file %q is not a restore staging file for %q", e.Staged, e.Path)
		}
		if len(e.SHA256) != 64 || strings.Trim(e.SHA256, "0123456789abcdef") != "" {
			return fmt.Errorf("restore journal's entry for %q has no valid SHA-256 of its staged content", e.Path)
		}
	}
	if j.WitnessPath != "" || j.WitnessValue != "" {
		want, err := filepath.Abs(auditverify.WitnessPath(identityPath))
		if err != nil {
			return err
		}
		if j.WitnessPath != want {
			return fmt.Errorf("restore journal's rollback-protection witness path %q is not this deployment's witness file %q", j.WitnessPath, want)
		}
	}
	return nil
}

func sqliteDBPath(cfg *config.Config) string {
	if cfg.Storage.Database.Path == "" {
		return "./secrets.db"
	}
	return cfg.Storage.Database.Path
}
