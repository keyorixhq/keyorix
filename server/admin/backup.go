// backup.go implements `keyorix-server admin backup` (ADR-108 §B3,
// design-b3-backup-v2.md): a consistent, offline, backend-neutral logical
// snapshot of the database and every encryption key-material file, taken
// while this admin command holds the database exclusively
// (acquireDatabaseLock) -- the same "operations that need the database to
// themselves" guarantee every other admin command relies on.
//
// A complete backup is TWO things -- the database and the keys -- matching
// docs/SELF_HOSTING.md §5's existing manual guidance for the Docker/Postgres
// deployment shape. Every backup now writes the v2 logical format
// (internal/backupfmt) unconditionally -- design §3.6's explicit decision:
// no --format=physical escape hatch, no conditional/opt-in physical mode.
// `admin restore` still reads an old v1-physical-format archive (backup_v1_
// legacy.go) until Keyorix 1.0; this command never produces one again.
package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// auditHighWaterMetadataKey is the system_metadata key internal/core's
// advanceAuditHighWater (audit_checkpoint.go) writes under -- must stay
// byte-for-byte identical to that unexported constant and to
// internal/auditverify's own copy (verify.go), since all three read/write
// the exact same row. Duplicated rather than imported: server/admin cannot
// reach internal/core's unexported constant, and this package already has
// its own direct-SQL access pattern to the raw DB.
const auditHighWaterMetadataKey = "audit_checkpoint_highwater" // #nosec G101 -- metadata key name, not a credential

var (
	backupOutput           string
	backupPassphraseSource crypto.PassphraseSource
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a consistent offline backup of the database and encryption keys",
	Long: `Writes a single archive (--output) containing a consistent, backend-neutral
logical snapshot of the configured database AND every encryption
key-material file (internal/keyfiles.Registry -- the same enumeration
'admin audit' checks). Neither alone is a usable backup: the database
without the keys is unreadable ciphertext, the keys without the database
are useless.

The archive's per-table manifest is signed (HMAC-SHA256, KEK-derived key,
design-b3-backup-v2.md §5) so tampering is caught by 'admin restore' before
any byte reaches the target -- not only by a post-hoc 'admin verify-audit'.

Consistency is guaranteed by the same exclusive database lock every admin
command takes: no server (or other admin command) can be writing while this
runs.

Only local/sqlite storage is supported today. For a Postgres-backed
deployment, back up with pg_dump directly (see docs/SELF_HOSTING.md §5).

--output must not already exist: each backup is a distinct, timestamped
artifact. Store it OFF this host -- a backup that never leaves the machine
it was taken on protects against nothing.

Restore with: keyorix-server admin restore --input <archive>`,
	RunE: runAdminBackup,
}

func init() {
	backupCmd.Flags().StringVar(&backupOutput, "output", "", "Path to write the backup archive to (must not already exist; required)")
	registerPassphraseFlags(backupCmd, &backupPassphraseSource)
	rootCmd.AddCommand(backupCmd)
}

func runAdminBackup(cmd *cobra.Command, args []string) error {
	if backupOutput == "" {
		return fmt.Errorf("--output is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" {
		return fmt.Errorf("admin backup only supports local/sqlite storage today (got %q) -- "+
			"for Postgres, back up with pg_dump directly (see docs/SELF_HOSTING.md §5)", cfg.Storage.Type)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	manifestKey, err := unwrapManifestKey(cfg, ".", backupPassphraseSource)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(manifestKey)

	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	if info, statErr := os.Stat(dbPath); statErr == nil {
		if err := backupfmt.CheckFreeSpace(backupOutput, info.Size()); err != nil {
			return fmt.Errorf("preflight free-space check (design §7.4): %w", err)
		}
	}

	keyEntries, keyBlobs, err := readKeyFilesForBackup(cfg)
	if err != nil {
		return err
	}

	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}
	defer closeGormDB(gdb)

	highWater, err := readAuditHighWater(gdb)
	if err != nil {
		return fmt.Errorf("read audit high-water mark: %w", err)
	}

	f, err := os.OpenFile(backupOutput, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- operator-supplied output path, the whole point of this flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("--output %q already exists -- each backup is a distinct artifact, pick a new path (e.g. include a timestamp)", backupOutput)
		}
		return fmt.Errorf("create %q: %w", backupOutput, err)
	}

	manifest, werr := backupfmt.WriteBackup(gdb, storage.CurrentSchemaEpoch(), highWater, manifestKey, keyEntries, keyBlobs, f)
	if werr != nil {
		_ = f.Close()
		_ = os.Remove(backupOutput)
		return fmt.Errorf("write backup archive: %w", werr)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(backupOutput)
		return fmt.Errorf("close %q: %w", backupOutput, err)
	}

	if len(manifest.DanglingReferences) > 0 {
		fmt.Printf("WARNING: this backup's source database has %d pre-existing dangling reference(s) "+
			"(design §3.4) -- see the archive's MANIFEST.json for details. This backup itself succeeded; "+
			"a restore from it will refuse to load until these are fixed at the source.\n", len(manifest.DanglingReferences))
	}

	var totalRows int64
	for _, te := range manifest.Tables {
		totalRows += te.RowCount
	}
	fmt.Printf("Backup written to %s (%d table(s), %d row(s) total, %d key file(s))\n",
		backupOutput, len(manifest.Tables), totalRows, len(keyEntries))
	fmt.Println("Store this archive OFF this host. Restore with:")
	fmt.Printf("  keyorix-server admin restore --input %s\n", backupOutput)

	recordAdminAction(cfg, "admin.backup_created",
		fmt.Sprintf("created backup archive %s (%d table(s), %d row(s), %d key file(s))",
			backupOutput, len(manifest.Tables), totalRows, len(keyEntries)), true)
	return nil
}

// unwrapManifestKey performs the same "KEK/passphrase access" step `admin
// diagnose`'s diagnoseEncryption already does (real KEK derivation, under
// the exclusive DEK lock, released via Shutdown), then returns the
// KEK-derived backup-manifest signing key (design §5.2) -- the raw KEK
// itself never leaves internal/encryption. baseDir is where the encryption
// service looks for key-material files relative to cfg.Storage.Encryption's
// configured paths: "." for `admin backup` (the real, current key files);
// a staging directory laid out to match those same relative paths for
// `admin restore` (design §5.3: unwrap from the archive's own STAGED, still
// -wrapped key files, never the real target's, since a fresh restore target
// has none yet).
func unwrapManifestKey(cfg *config.Config, baseDir string, passphraseSource crypto.PassphraseSource) ([]byte, error) {
	providerType := cfg.Storage.Encryption.KeyProvider.Type
	var passphrase string
	if providerType == "" || providerType == "password" {
		passphraseBytes, err := crypto.ResolvePassphrase(passphraseSource, "KEYORIX_MASTER_PASSWORD")
		if err != nil {
			return nil, fmt.Errorf("no master passphrase available (%w); set KEYORIX_MASTER_PASSWORD, pass "+
				"--passphrase-fd/--passphrase-file/--passphrase-stdin, or configure storage.encryption.key_provider "+
				"(file/env/aws-kms)", err)
		}
		defer crypto.WipeBytes(passphraseBytes)
		passphrase = string(passphraseBytes)
	}

	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("failed to acquire the encryption key lock (another process is using it): %w", err)
	}
	defer svc.Shutdown()

	if err := svc.Initialize(passphrase); err != nil {
		return nil, fmt.Errorf("failed to derive/verify the KEK: %w", err)
	}
	key, _, ok := svc.BackupManifestKey()
	if !ok {
		return nil, fmt.Errorf("backup-manifest signing key unavailable (encryption not enabled?)")
	}
	return key, nil
}

// readKeyFilesForBackup reads every file internal/keyfiles.Registry
// enumerates and computes its checksum -- unchanged from v1 (design §1: no
// new subcommands or UX for key-material handling).
func readKeyFilesForBackup(cfg *config.Config) ([]backupfmt.KeyFileEntry, [][]byte, error) {
	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		return nil, nil, fmt.Errorf("build key-file registry: %w", err)
	}
	entries := make([]backupfmt.KeyFileEntry, len(specs))
	blobs := make([][]byte, len(specs))
	for i, spec := range specs {
		data, rerr := os.ReadFile(spec.Path) // #nosec G304 -- config-driven path, sanitized by keyfiles.SafePath
		if rerr != nil {
			return nil, nil, fmt.Errorf("read key file %q: %w", spec.Path, rerr)
		}
		sum := sha256.Sum256(data)
		entries[i] = backupfmt.KeyFileEntry{
			OriginalPath: spec.Path,
			TarName:      fmt.Sprintf("keyfiles/%d", i),
			Mode:         uint32(spec.Mode),
			SHA256:       hex.EncodeToString(sum[:]),
			Size:         int64(len(data)),
		}
		blobs[i] = data
	}
	return entries, blobs, nil
}

// readAuditHighWater reads the raw "audit_checkpoint_highwater"
// system_metadata value from the SAME connection backupfmt.WriteBackup will
// read table data from, under the SAME exclusive lock, so it reflects
// exactly the state being backed up -- empty if no checkpoint has ever been
// written on this install (a fresh/young install, not an error).
func readAuditHighWater(gdb *gorm.DB) (string, error) {
	var meta models.SystemMetadata
	err := gdb.Where("key = ?", auditHighWaterMetadataKey).Take(&meta).Error
	switch {
	case err == nil:
		return meta.Value, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "", nil
	default:
		return "", err
	}
}
