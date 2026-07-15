// migrate_provider.go — `keyorix encryption migrate-provider`.
//
// Re-wraps the DEK under a KEK from a different provider (ADR-041) so an existing
// install can move between KEK providers — most importantly password/file/env → a
// cloud KMS — without re-encrypting any data. Only the DEK's wrapping changes; the
// operation is fast and takes no database lock. After re-wrapping it verifies the
// target provider unwraps the DEK (round-tripping a probe value through a fresh
// service) and keeps a timestamped backup of the previous wrapped DEK, restoring it
// if verification fails.
package encryption

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

const (
	azureKMSProvider = "azure-kms"
)

// newMasterPasswordEnv holds the new master passphrase when migrating TO the
// password provider (kept distinct from KEYORIX_MASTER_PASSWORD, which is the
// current one).
const newMasterPasswordEnv = "KEYORIX_NEW_MASTER_PASSWORD" // #nosec G101 -- env var name, not a credential

var (
	mpToType                 string
	mpToKMSKeyID             string
	mpToWrappedKeyPath       string
	mpToKMSEncryptionContext map[string]string
	mpToFilePath             string
	mpToEnvVar               string
	mpToExecCommand          []string
	mpToShareFiles           []string
	mpToShareEnv             []string
	mpToShareCommitment      string
	mpToTPMDevice            string
	mpToSaltPath             string
	mpConfirm                bool

	mpCleanupConfirm bool
	mpCleanupDryRun  bool
)

var migrateProviderCmd = &cobra.Command{
	Use:   "migrate-provider",
	Short: "Migrate the KEK to a different key provider without re-encrypting data",
	Long: `Re-wrap the data-encryption key (DEK) with a key-encryption key (KEK) from a
different provider — for example, move an existing install from a password-derived
KEK to a cloud KMS (ADR-041). Only the DEK's wrapping changes; secret values are
never re-encrypted, so this is fast and does not lock the database.

The CURRENT provider comes from the loaded config (storage.encryption.key_provider).
The TARGET provider is described by the --to-* flags. After re-wrapping, the tool
verifies the target provider unwraps the DEK before keeping the change and writes a
timestamped backup of the previous wrapped DEK (restoring it if verification fails).

When migrating TO the password provider, set ` + newMasterPasswordEnv + ` to the new
master passphrase.

Run on the server host (local storage). Requires --confirm. After it succeeds,
update storage.encryption.key_provider in your config to the target before the next
restart — the printed summary shows the exact block.`,
	RunE: runMigrateProvider,
}

// migrateProviderCleanupCmd securely deletes leftover `<dekPath>.migrate-backup.*`
// files (#198). migrate-provider retains its pre-migration wrapped-DEK backup
// indefinitely by design (so a failed verification can restore it) — but since a
// rewrap never changes the DEK's VALUE, only its wrapping, the backup's
// plaintext-after-unwrap stays byte-identical to the DEK still in active use. A
// weak/compromised OLD KEK can unwrap it forever unless an operator deletes it, and
// the only prior guidance was a printed "remove once confident" — no tooling.
var migrateProviderCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Securely delete leftover pre-migration wrapped-DEK backups",
	Long: `Find and securely delete every "<dek_path>.migrate-backup.*" file left behind by
a previous 'migrate-provider' run. Each backup's plaintext-after-unwrap is
byte-identical to the DEK still in active use (only the wrapping changed), so a
weak/compromised OLD key-encryption key can still unwrap it indefinitely — deleting
these once you've confirmed the new provider works removes that exposure window.

Files are overwritten (random pass, then zero pass, each fsynced) before being
unlinked — a best-effort "shred", not a guarantee on copy-on-write filesystems, SSDs,
or replicated/snapshotted storage. Requires --confirm; use --dry-run to preview first.`,
	RunE: runMigrateProviderCleanup,
}

func init() {
	EncryptionCmd.AddCommand(migrateProviderCmd)
	f := migrateProviderCmd.Flags()
	f.StringVar(&mpToType, "to-type", "", "target provider: password|file|env|exec|shamir|tpm|aws-kms|gcp-kms|azure-kms (required)")
	f.StringVar(&mpToKMSKeyID, "to-kms-key-id", "", "target KMS key id/ARN/resource-name/URL (kms types)")
	f.StringVar(&mpToWrappedKeyPath, "to-wrapped-key-path", "", "where to store the KMS-wrapped KEK blob (kms types)")
	f.StringToStringVar(&mpToKMSEncryptionContext, "to-kms-encryption-context", nil,
		"encryption context/AAD binding the wrapped KEK to this install (aws-kms/gcp-kms only, e.g. keyorix-install=prod-1); "+
			"pair with a NEW --to-wrapped-key-path to durably re-wrap under it — #123")
	f.StringVar(&mpToFilePath, "to-file-path", "", "path to the raw KEK material (file type)")
	f.StringVar(&mpToEnvVar, "to-env-var", "", "env var holding the raw KEK (env type)")
	f.StringSliceVar(&mpToExecCommand, "to-exec-command", nil, "resolver argv whose stdout supplies the KEK (exec type), e.g. op,read,op://vault/kek/value")
	f.StringSliceVar(&mpToShareFiles, "to-shamir-share-files", nil, "paths to >=threshold Shamir share files (shamir type)")
	f.StringSliceVar(&mpToShareEnv, "to-shamir-share-env", nil, "env var names holding Shamir shares (shamir type)")
	f.StringVar(&mpToShareCommitment, "to-shamir-commitment", "", "hex KEK commitment printed by `shamir-split` for these shares (shamir type; recommended — #429)")
	f.StringVar(&mpToTPMDevice, "to-tpm-device", "", "TPM 2.0 device path (tpm type; default /dev/tpmrm0)")
	f.StringVar(&mpToSaltPath, "to-salt-path", "", "salt path for the target password provider (default: current salt_path)")
	f.BoolVar(&mpConfirm, "confirm", false, "required acknowledgement before re-wrapping the DEK")

	migrateProviderCmd.AddCommand(migrateProviderCleanupCmd)
	cf := migrateProviderCleanupCmd.Flags()
	cf.BoolVar(&mpCleanupConfirm, "confirm", false, "required acknowledgement before deleting backup files")
	cf.BoolVar(&mpCleanupDryRun, "dry-run", false, "list matching backup files without deleting them")
}

// runMigrateProviderCleanup finds and (unless --dry-run) securely deletes every
// migrate-backup file for the configured DEK path. Matching is by filename prefix
// "<base>.migrate-backup." directly under the DEK's directory — the same layout
// migrateProviderWithConfig writes (backupRel is relative to baseDir, sibling to
// enc.DEKPath).
func runMigrateProviderCleanup(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	baseDir, _ := os.Getwd()
	return migrateProviderCleanupWithConfig(cfg, baseDir, mpCleanupDryRun, mpCleanupConfirm)
}

// migrateProviderCleanupWithConfig is the testable core of the cleanup subcommand:
// no flag parsing, an explicit baseDir instead of os.Getwd().
func migrateProviderCleanupWithConfig(cfg *config.Config, baseDir string, dryRun, confirm bool) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	matches, err := findMigrateBackups(baseDir, cfg.Storage.Encryption.DEKPath)
	if err != nil {
		return fmt.Errorf("failed to scan for migrate-backup files: %w", err)
	}
	if len(matches) == 0 {
		fmt.Println("✅ No migrate-backup files found — nothing to clean up.")
		return nil
	}
	fmt.Printf("Found %d migrate-backup file(s):\n", len(matches))
	for _, m := range matches {
		fmt.Printf("  %s\n", m)
	}
	if dryRun {
		fmt.Println("\n(--dry-run: no files deleted)")
		return nil
	}
	if !confirm {
		return fmt.Errorf("this permanently and irreversibly shreds the listed backup file(s). Re-run with --confirm (or --dry-run to only list them)")
	}
	for _, m := range matches {
		if err := securefiles.SecureDeleteFile(filepath.Join(baseDir, m)); err != nil {
			return fmt.Errorf("failed to securely delete %s: %w", m, err)
		}
	}
	fmt.Printf("✅ Securely deleted %d migrate-backup file(s).\n", len(matches))
	return nil
}

// findMigrateBackups lists filenames (relative to baseDir) matching
// "<base>.migrate-backup.*" for the given DEK path, sorted for stable output.
func findMigrateBackups(baseDir, dekPath string) ([]string, error) {
	dir := filepath.Dir(filepath.Join(baseDir, dekPath))
	prefix := filepath.Base(dekPath) + ".migrate-backup."
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		rel, rerr := filepath.Rel(baseDir, filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		matches = append(matches, rel)
	}
	sort.Strings(matches)
	return matches, nil
}

// migrateOpts is the target-provider description, mirroring the --to-* flags so the
// core can be unit-tested without cobra.
type migrateOpts struct {
	toType                 string
	toKMSKeyID             string
	toWrappedKeyPath       string
	toKMSEncryptionContext map[string]string
	toFilePath             string
	toEnvVar               string
	toExecCommand          []string
	toShareFiles           []string
	toShareEnv             []string
	toShareCommitment      string
	toTPMDevice            string
	toSaltPath             string
}

func runMigrateProvider(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	opts := migrateOpts{
		toType:                 mpToType,
		toKMSKeyID:             mpToKMSKeyID,
		toWrappedKeyPath:       mpToWrappedKeyPath,
		toKMSEncryptionContext: mpToKMSEncryptionContext,
		toFilePath:             mpToFilePath,
		toEnvVar:               mpToEnvVar,
		toExecCommand:          mpToExecCommand,
		toShareFiles:           mpToShareFiles,
		toShareEnv:             mpToShareEnv,
		toShareCommitment:      mpToShareCommitment,
		toTPMDevice:            mpToTPMDevice,
		toSaltPath:             mpToSaltPath,
	}
	return migrateProviderWithConfig(cfg, opts, mpConfirm)
}

// targetEncryptionConfig derives the target EncryptionConfig from the current one
// plus the --to-* options. The DEK path is preserved (the same dek.key is re-wrapped
// in place); only the key_provider (and, for password, optionally the salt path)
// changes.
func targetEncryptionConfig(cur *config.EncryptionConfig, opts migrateOpts) (config.EncryptionConfig, error) { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	tgt := *cur
	kp := config.KeyProviderConfig{Type: opts.toType}
	switch opts.toType {
	case "password":
		if opts.toSaltPath != "" {
			tgt.SaltPath = opts.toSaltPath
		}
	case "file":
		if opts.toFilePath == "" {
			return tgt, fmt.Errorf("--to-file-path is required for --to-type file")
		}
		kp.FilePath = opts.toFilePath
	case "env":
		if opts.toEnvVar == "" {
			return tgt, fmt.Errorf("--to-env-var is required for --to-type env")
		}
		kp.EnvVar = opts.toEnvVar
	case "exec":
		if len(opts.toExecCommand) == 0 {
			return tgt, fmt.Errorf("--to-exec-command is required for --to-type exec")
		}
		kp.ExecCommand = opts.toExecCommand
	case "shamir":
		if len(opts.toShareFiles)+len(opts.toShareEnv) < 2 {
			return tgt, fmt.Errorf("--to-type shamir requires at least 2 shares via --to-shamir-share-files/--to-shamir-share-env (the threshold)")
		}
		kp.ShamirShareFiles = opts.toShareFiles
		kp.ShamirShareEnv = opts.toShareEnv
		kp.ShamirCommitment = opts.toShareCommitment
	case "tpm":
		if opts.toWrappedKeyPath == "" {
			return tgt, fmt.Errorf("--to-wrapped-key-path is required for --to-type tpm (where the sealed KEK blob lives)")
		}
		if opts.toWrappedKeyPath == tgt.DEKPath {
			return tgt, fmt.Errorf("--to-wrapped-key-path must differ from the DEK path (%s)", tgt.DEKPath)
		}
		kp.TPMDevice = opts.toTPMDevice
		kp.WrappedKeyPath = opts.toWrappedKeyPath
	case "aws-kms", "gcp-kms", azureKMSProvider:
		if opts.toKMSKeyID == "" {
			return tgt, fmt.Errorf("--to-kms-key-id is required for --to-type %s", opts.toType)
		}
		if opts.toWrappedKeyPath == "" {
			return tgt, fmt.Errorf("--to-wrapped-key-path is required for --to-type %s", opts.toType)
		}
		if opts.toWrappedKeyPath == tgt.DEKPath {
			return tgt, fmt.Errorf("--to-wrapped-key-path must differ from the DEK path (%s)", tgt.DEKPath)
		}
		// #123: azure-kms (RSA-OAEP wrap) has no AAD input — matches
		// NewKeyProviderFromConfig's hard rejection, checked here too so this fails
		// before any DEK backup/re-wrap work rather than after.
		if opts.toType == azureKMSProvider && len(opts.toKMSEncryptionContext) > 0 {
			return tgt, fmt.Errorf("--to-kms-encryption-context is not supported for --to-type azure-kms (RSA-OAEP key wrap has no AAD input)")
		}
		// KMSKeyProvider.KEK() only re-wraps (and so only applies a NEW encryption
		// context) when generating a FRESH KEK at a wrapped_key_path that doesn't yet
		// exist — pointing at an existing path takes the decrypt-the-existing-blob
		// path instead, which does not rebind it. Requiring a genuinely new path when
		// a context is supplied keeps this flag from silently no-op-ing.
		if len(opts.toKMSEncryptionContext) > 0 && opts.toType == cur.KeyProvider.Type && opts.toWrappedKeyPath == cur.KeyProvider.WrappedKeyPath {
			return tgt, fmt.Errorf("--to-kms-encryption-context requires a NEW --to-wrapped-key-path (got the current one, %q): re-wrapping under a context only takes effect when a fresh KEK is generated", opts.toWrappedKeyPath)
		}
		kp.KMSKeyID = opts.toKMSKeyID
		kp.WrappedKeyPath = opts.toWrappedKeyPath
		kp.KMSEncryptionContext = opts.toKMSEncryptionContext
	default:
		return tgt, fmt.Errorf("unknown --to-type %q (supported: password, file, env, exec, shamir, tpm, aws-kms, gcp-kms, azure-kms)", opts.toType)
	}
	tgt.KeyProvider = kp
	return tgt, nil
}

// targetPassphrase resolves the passphrase for the TARGET provider. Only the
// password provider needs one (from KEYORIX_NEW_MASTER_PASSWORD); the others source
// the KEK from key material / KMS and return "".
func targetPassphrase(providerType string) (string, error) {
	if providerType != "" && providerType != "password" {
		return "", nil
	}
	p := os.Getenv(newMasterPasswordEnv)
	if p == "" {
		return "", fmt.Errorf("target provider is password — set %s to the new master passphrase", newMasterPasswordEnv)
	}
	return p, nil
}

// migrateProviderWithConfig is the testable core: it does no flag parsing and takes
// an explicit confirm. The validation gates (encryption enabled, local storage,
// target-config sanity, --confirm) all return before any key/DB work, so structural
// tests can exercise them without key files.
func migrateProviderWithConfig(cfg *config.Config, opts migrateOpts, confirm bool) error {
	enc := &cfg.Storage.Encryption
	if !enc.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("KEK-provider migration must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}
	if opts.toType == "" {
		return fmt.Errorf("--to-type is required (password|file|env|exec|shamir|tpm|aws-kms|gcp-kms|azure-kms)")
	}
	tgtEnc, err := targetEncryptionConfig(enc, opts)
	if err != nil {
		return err
	}
	if !confirm {
		return fmt.Errorf("this re-wraps the DEK and changes the KEK provider. Re-run with --confirm")
	}

	baseDir, _ := os.Getwd()

	oldPass, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}
	newPass, err := targetPassphrase(tgtEnc.KeyProvider.Type)
	if err != nil {
		return err
	}

	// 1. Open with the CURRENT provider — unwraps the DEK into memory.
	oldSvc := encryption.NewService(enc, baseDir)
	if err := oldSvc.Initialize(oldPass); err != nil {
		return fmt.Errorf("failed to open encryption with the current provider: %w", err)
	}
	defer oldSvc.Shutdown()

	// 2. Encrypt a probe value under the current DEK — used after re-wrapping to
	//    verify the target provider yields the *same* DEK (data still decryptable).
	probe := []byte("keyorix-kek-provider-migration-probe")
	probeCT, _, err := oldSvc.EncryptSecret(probe)
	if err != nil {
		return fmt.Errorf("failed to encrypt verification probe: %w", err)
	}

	// 3. Back up the current wrapped DEK before overwriting it.
	backupRel := fmt.Sprintf("%s.migrate-backup.%d", enc.DEKPath, time.Now().Unix())
	if err := copyFile(filepath.Join(baseDir, enc.DEKPath), filepath.Join(baseDir, backupRel)); err != nil {
		return fmt.Errorf("failed to back up current wrapped DEK: %w", err)
	}

	// 4. Build the TARGET provider and re-wrap the DEK under it.
	newProvider, err := encryption.NewKeyProviderFromConfig(&tgtEnc, baseDir, newPass)
	if err != nil {
		_ = os.Remove(filepath.Join(baseDir, backupRel))
		return fmt.Errorf("failed to build target provider: %w", err)
	}
	fmt.Printf("🔄 Re-wrapping DEK: %s → %s provider...\n", providerLabel(enc.KeyProvider.Type), opts.toType)
	if err := oldSvc.RewrapDEKWithProvider(newProvider); err != nil {
		// RewrapDEK leaves the active DEK untouched on failure — drop the backup.
		_ = os.Remove(filepath.Join(baseDir, backupRel))
		return fmt.Errorf("re-wrap failed — no changes made to the active DEK: %w", err)
	}

	// 5. Verify a fresh service on the TARGET config unwraps the DEK and decrypts
	//    the probe. On any mismatch, restore the previous wrapped DEK and abort.
	verifySvc := encryption.NewService(&tgtEnc, baseDir)
	if err := verifySvc.Initialize(newPass); err != nil {
		restoreBackup(baseDir, backupRel, enc.DEKPath)
		return fmt.Errorf("verification failed (target provider could not open) — restored previous DEK: %w", err)
	}
	defer verifySvc.Shutdown()
	got, err := verifySvc.DecryptSecret(probeCT)
	if err != nil || !bytes.Equal(got, probe) {
		restoreBackup(baseDir, backupRel, enc.DEKPath)
		return fmt.Errorf("verification failed (probe did not round-trip under the target provider) — restored previous DEK")
	}

	printMigrateSummary(tgtEnc, backupRel)
	return nil
}

// copyFile copies src to dst with 0600 permissions, fsyncing the destination file
// and its directory so the copy is durable. The backup this produces is the
// rollback target if migration verification fails — a non-durable backup lost to a
// crash could leave neither a valid old nor new wrapped DEK on disk.
//
// O_NOFOLLOW refuses to write THROUGH a final-component symlink at dst: without
// it, an attacker with write access to dst's parent directory (the DEK's own
// directory, or the migrate-backup path next to it) could pre-plant a symlink
// there pointing at an arbitrary file this process can write, and the backup/
// restore write would silently clobber that file instead of the intended DEK/
// backup path. With O_NOFOLLOW the open fails (ELOOP) instead of following it —
// the same protection securefiles.SecureWriteFile applies to its writes.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- operator-configured key path under baseDir
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600) // #nosec G304 -- operator-configured key path under baseDir (local CLI tool, not network input)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	return securefiles.SyncDir(filepath.Dir(dst))
}

// restoreBackup copies the backup back over the active DEK path. Best-effort: logs
// to stderr if the restore itself fails so the operator can recover manually.
func restoreBackup(baseDir, backupRel, dekPath string) {
	if err := copyFile(filepath.Join(baseDir, backupRel), filepath.Join(baseDir, dekPath)); err != nil {
		fmt.Fprintf(os.Stderr, "❌ CRITICAL: failed to restore DEK backup %s → %s: %v\n  Restore it manually before restarting.\n", backupRel, dekPath, err)
	}
}

func providerLabel(t string) string {
	if t == "" {
		return "password"
	}
	return t
}

func printMigrateSummary(tgt config.EncryptionConfig, backupRel string) {
	kp := tgt.KeyProvider
	fmt.Println("✅ DEK re-wrapped and verified under the new provider.")
	fmt.Printf("🗄️  Previous wrapped DEK backed up at %s.\n", backupRel)
	fmt.Println("   Its plaintext-after-unwrap is byte-identical to the DEK still in active use —")
	fmt.Println("   only the wrapping changed. Once you've confirmed the new provider works, run")
	fmt.Println("   `keyorix encryption migrate-provider cleanup --confirm` to securely delete it")
	fmt.Println("   (and any other leftover migrate-backup files) rather than a plain rm.")
	fmt.Println()
	fmt.Println("⚠️  Update storage.encryption.key_provider in your config to match BEFORE the next restart:")
	fmt.Println()
	fmt.Println("    key_provider:")
	fmt.Printf("      type: %s\n", kp.Type)
	switch kp.Type {
	case "file":
		fmt.Printf("      file_path: %s\n", kp.FilePath)
	case "env":
		fmt.Printf("      env_var: %s\n", kp.EnvVar)
	case "exec":
		fmt.Printf("      exec_command: %v\n", kp.ExecCommand)
	case "shamir":
		if len(kp.ShamirShareFiles) > 0 {
			fmt.Printf("      shamir_share_files: %v\n", kp.ShamirShareFiles)
		}
		if len(kp.ShamirShareEnv) > 0 {
			fmt.Printf("      shamir_share_env: %v\n", kp.ShamirShareEnv)
		}
		if kp.ShamirCommitment != "" {
			fmt.Printf("      shamir_commitment: %s\n", kp.ShamirCommitment)
		} else {
			fmt.Println("      # shamir_commitment: not set — pass --to-shamir-commitment (the value")
			fmt.Println("      # printed by `shamir-split` for these shares) for real cryptographic")
			fmt.Println("      # verification of the reconstructed KEK (#429); without it, unseal falls")
			fmt.Println("      # back to a weaker, forgeable check and logs a loud warning at startup.")
		}
	case "tpm":
		if kp.TPMDevice != "" {
			fmt.Printf("      tpm_device: %s\n", kp.TPMDevice)
		}
		fmt.Printf("      wrapped_key_path: %s\n", kp.WrappedKeyPath)
	case "aws-kms", "gcp-kms", azureKMSProvider:
		fmt.Printf("      kms_key_id: %s\n", kp.KMSKeyID)
		fmt.Printf("      wrapped_key_path: %s\n", kp.WrappedKeyPath)
	case "password":
		fmt.Printf("      # salt_path: %s (set storage.encryption.salt_path)\n", tgt.SaltPath)
		fmt.Printf("      # the master passphrase is now %s — set KEYORIX_MASTER_PASSWORD to it\n", newMasterPasswordEnv)
	}
	fmt.Println()
	fmt.Println("⚠️  Unlike a `rotate`, this changes the KEK — and with it, the compliance-")
	fmt.Println("   evidence-pack signing key (#268). Any evidence pack signed BEFORE this")
	fmt.Println("   migration will report as \"superseded key version\" (not tampered) under")
	fmt.Println("   `keyorix compliance verify` from now on; a routine `encryption rotate`")
	fmt.Println("   does NOT have this effect. Run `compliance verify` on any outstanding")
	fmt.Println("   packs before this step if you need to confirm they're still valid.")
}
