// migrate_provider.go — the testable core of `encryption migrate-provider`
// (and its `cleanup` subcommand).
//
// Re-wraps the DEK under a KEK from a different provider (ADR-041) so an existing
// install can move between KEK providers — most importantly password/file/env → a
// cloud KMS — without re-encrypting any data. Only the DEK's wrapping changes; the
// operation is fast and rewrites no data rows. It does hold the exclusive
// key-directory lock (dek.lock) from start to finish (openKeyWriter), so it
// refuses to run beside a live server or another key writer; `migrate-provider
// cleanup` holds the same lock for its whole run, --dry-run included. After
// re-wrapping it verifies the target provider unwraps the DEK (round-tripping a
// probe value through a fresh service) and keeps a timestamped backup of the
// previous wrapped DEK, restoring it if verification fails.
package encryptionops

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"golang.org/x/sys/unix"
)

const (
	azureKMSProvider = "azure-kms"
)

// MigrateOpts is the target-provider description — mirrors the old CLI's
// --to-* flags so this core can be driven by any caller's own flag set
// without a cobra dependency.
type MigrateOpts struct {
	ToType                 string
	ToKMSKeyID             string
	ToWrappedKeyPath       string
	ToKMSEncryptionContext map[string]string
	ToFilePath             string
	ToEnvVar               string
	ToExecCommand          []string
	ToShareFiles           []string
	ToShareEnv             []string
	ToShareCommitment      string
	ToTPMDevice            string
	ToSaltPath             string
}

// TargetEncryptionConfig derives the target EncryptionConfig from the current one
// plus the --to-* options. The DEK path is preserved (the same dek.key is re-wrapped
// in place); only the key_provider (and, for password, optionally the salt path)
// changes.
func TargetEncryptionConfig(cur *config.EncryptionConfig, opts MigrateOpts) (config.EncryptionConfig, error) { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	tgt := *cur
	kp := config.KeyProviderConfig{Type: opts.ToType}
	switch opts.ToType {
	case "password":
		if opts.ToSaltPath != "" {
			tgt.SaltPath = opts.ToSaltPath
		}
	case "file":
		if opts.ToFilePath == "" {
			return tgt, fmt.Errorf("--to-file-path is required for --to-type file")
		}
		kp.FilePath = opts.ToFilePath
	case "env":
		if opts.ToEnvVar == "" {
			return tgt, fmt.Errorf("--to-env-var is required for --to-type env")
		}
		kp.EnvVar = opts.ToEnvVar
	case "exec":
		if len(opts.ToExecCommand) == 0 {
			return tgt, fmt.Errorf("--to-exec-command is required for --to-type exec")
		}
		kp.ExecCommand = opts.ToExecCommand
	case "shamir":
		if len(opts.ToShareFiles)+len(opts.ToShareEnv) < 2 {
			return tgt, fmt.Errorf("--to-type shamir requires at least 2 shares via --to-shamir-share-files/--to-shamir-share-env (the threshold)")
		}
		// The commitment is required here (REVIEW-ENCRYPTIONOPS-1 F5): without it,
		// whoever holds threshold-1 genuine shares can forge one more that makes the
		// reconstructed KEK any value they choose (#429), and the DEK would be
		// wrapped under it. A migration is a new binding, so unlike a running
		// install's pre-#429 split there is nothing to stay compatible with.
		commitment := strings.TrimSpace(opts.ToShareCommitment)
		if c, err := hex.DecodeString(commitment); err != nil || len(c) != sha256.Size {
			return tgt, fmt.Errorf("--to-shamir-commitment is required for --to-type shamir and must be the %d-hex-character value `shamir-split` printed for these shares: without it, a holder of threshold-1 shares can forge a share that sets the KEK (#429)", 2*sha256.Size)
		}
		kp.ShamirShareFiles = opts.ToShareFiles
		kp.ShamirShareEnv = opts.ToShareEnv
		kp.ShamirCommitment = commitment
	case "tpm":
		if opts.ToWrappedKeyPath == "" {
			return tgt, fmt.Errorf("--to-wrapped-key-path is required for --to-type tpm (where the sealed KEK blob lives)")
		}
		if opts.ToWrappedKeyPath == tgt.DEKPath {
			return tgt, fmt.Errorf("--to-wrapped-key-path must differ from the DEK path (%s)", tgt.DEKPath)
		}
		kp.TPMDevice = opts.ToTPMDevice
		kp.WrappedKeyPath = opts.ToWrappedKeyPath
	case "aws-kms", "gcp-kms", azureKMSProvider:
		if opts.ToKMSKeyID == "" {
			return tgt, fmt.Errorf("--to-kms-key-id is required for --to-type %s", opts.ToType)
		}
		if opts.ToWrappedKeyPath == "" {
			return tgt, fmt.Errorf("--to-wrapped-key-path is required for --to-type %s", opts.ToType)
		}
		if opts.ToWrappedKeyPath == tgt.DEKPath {
			return tgt, fmt.Errorf("--to-wrapped-key-path must differ from the DEK path (%s)", tgt.DEKPath)
		}
		// #123: azure-kms (RSA-OAEP wrap) has no AAD input — matches
		// NewKeyProviderFromConfig's hard rejection, checked here too so this fails
		// before any DEK backup/re-wrap work rather than after.
		if opts.ToType == azureKMSProvider && len(opts.ToKMSEncryptionContext) > 0 {
			return tgt, fmt.Errorf("--to-kms-encryption-context is not supported for --to-type azure-kms (RSA-OAEP key wrap has no AAD input)")
		}
		// KMSKeyProvider.KEK() only re-wraps (and so only applies a NEW encryption
		// context) when generating a FRESH KEK at a wrapped_key_path that doesn't yet
		// exist — pointing at an existing path takes the decrypt-the-existing-blob
		// path instead, which does not rebind it. Requiring a genuinely new path when
		// a context is supplied keeps this flag from silently no-op-ing.
		if len(opts.ToKMSEncryptionContext) > 0 && opts.ToType == cur.KeyProvider.Type && opts.ToWrappedKeyPath == cur.KeyProvider.WrappedKeyPath {
			return tgt, fmt.Errorf("--to-kms-encryption-context requires a NEW --to-wrapped-key-path (got the current one, %q): re-wrapping under a context only takes effect when a fresh KEK is generated", opts.ToWrappedKeyPath)
		}
		kp.KMSKeyID = opts.ToKMSKeyID
		kp.WrappedKeyPath = opts.ToWrappedKeyPath
		kp.KMSEncryptionContext = opts.ToKMSEncryptionContext
	default:
		return tgt, fmt.Errorf("unknown --to-type %q (supported: password, file, env, exec, shamir, tpm, aws-kms, gcp-kms, azure-kms)", opts.ToType)
	}
	tgt.KeyProvider = kp
	return tgt, nil
}

// TargetPassphrase resolves the passphrase for the TARGET provider. Only the
// password provider needs one (sourced per src's precedence, falling back to
// NewMasterPassphraseEnvVar); the others source the KEK from key material /
// KMS and return "".
func TargetPassphrase(providerType string, src crypto.PassphraseSource) (string, error) {
	if providerType != "" && providerType != "password" {
		return "", nil
	}
	passphraseBytes, err := crypto.ResolvePassphrase(src, NewMasterPassphraseEnvVar)
	if err != nil {
		return "", err
	}
	defer crypto.WipeBytes(passphraseBytes)
	return string(passphraseBytes), nil
}

// MigrateProviderWithConfig is the testable core of `encryption
// migrate-provider`. The validation gates (encryption enabled, local storage,
// target-config sanity, --confirm) all return before any key/DB work.
//
// Crash safety: the previous wrapped DEK is backed up (durably, fsynced)
// BEFORE the re-wrap, and the re-wrap itself only overwrites the active
// wrapped-DEK file after the new provider has been built successfully. A kill
// between the backup and the re-wrap leaves the OLD wrapped DEK untouched and
// a spare backup copy of it — re-running is safe. A kill DURING or
// immediately after RewrapDEKWithProvider but before this function's own
// verification step runs leaves the backup in place for a human to restore
// from manually (this function's own crash-free path restores it
// automatically on a verification FAILURE, but cannot run its own cleanup
// code if the process is killed); the DEK's plaintext value is unchanged
// either way, so no data is ever at risk of becoming undecryptable — at worst
// an operator must manually restore backupRel over the DEK path using the
// printed filename.
func MigrateProviderWithConfig(cfg *config.Config, opts MigrateOpts, confirm bool, oldSrc, newSrc crypto.PassphraseSource) error {
	enc := &cfg.Storage.Encryption
	if !enc.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("KEK-provider migration must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}
	if opts.ToType == "" {
		return fmt.Errorf("--to-type is required (password|file|env|exec|shamir|tpm|aws-kms|gcp-kms|azure-kms)")
	}
	tgtEnc, err := TargetEncryptionConfig(enc, opts)
	if err != nil {
		return err
	}
	if !confirm {
		return fmt.Errorf("this re-wraps the DEK and changes the KEK provider. Re-run with --confirm")
	}

	baseDir, _ := os.Getwd()

	oldPass, err := MasterPassphrase(cfg, oldSrc)
	if err != nil {
		return err
	}
	newPass, err := TargetPassphrase(tgtEnc.KeyProvider.Type, newSrc)
	if err != nil {
		return err
	}

	// 1. Open with the CURRENT provider — unwraps the DEK into memory — under the
	//    exclusive key lock and after DEK-rotation crash recovery: the re-wrap
	//    writes dek.key.pending, which after an interrupted rotation holds the
	//    only copy of the new DEK.
	oldSvc, db, err := openKeyWriter(cfg, baseDir, oldPass, "migrate the KEK provider")
	if err != nil {
		return err
	}
	defer oldSvc.Shutdown()
	closeGormDB(db)
	audit, err := openAuditKeyChange(cfg, oldSvc)
	if err != nil {
		return err
	}

	// 2. Encrypt a probe value under the current DEK — used after re-wrapping to
	//    verify the target provider yields the *same* DEK (data still decryptable).
	probe := []byte("keyorix-kek-provider-migration-probe")
	probeCT, _, err := oldSvc.EncryptSecret(probe)
	if err != nil {
		return fmt.Errorf("failed to encrypt verification probe: %w", err)
	}

	// 3. Back up the current wrapped DEK before overwriting it.
	backupRel, err := CreateMigrateBackup(baseDir, enc.DEKPath)
	if err != nil {
		return fmt.Errorf("failed to back up current wrapped DEK: %w", err)
	}

	// 4. Build the TARGET provider and re-wrap the DEK under it.
	newProvider, err := encryption.NewKeyProviderFromConfig(&tgtEnc, baseDir, newPass)
	if err != nil {
		_ = os.Remove(filepath.Join(baseDir, backupRel))
		return fmt.Errorf("failed to build target provider: %w", err)
	}
	fmt.Printf("🔄 Re-wrapping DEK: %s → %s provider...\n", ProviderLabel(enc.KeyProvider.Type), opts.ToType)
	if err := oldSvc.RewrapDEKWithProviderPrepare(newProvider, audit.prepare); err != nil {
		// RewrapDEK leaves the active DEK untouched on failure — drop the backup.
		_ = os.Remove(filepath.Join(baseDir, backupRel))
		return fmt.Errorf("re-wrap failed — no changes made to the active DEK: %w", err)
	}

	// 5. Verify a fresh service on the TARGET config unwraps the DEK and decrypts
	//    the probe. On any mismatch, restore the previous wrapped DEK and abort.
	verifySvc := encryption.NewService(&tgtEnc, baseDir)
	if err := verifySvc.Initialize(newPass); err != nil {
		RestoreBackup(baseDir, backupRel, enc.DEKPath, keySetWriter(enc, baseDir))
		return fmt.Errorf("verification failed (target provider could not open) — restored previous DEK (its copy %s is kept; `migrate-provider cleanup` removes it): %w", backupRel, err)
	}
	defer verifySvc.Shutdown()
	got, err := verifySvc.DecryptSecret(probeCT)
	if err != nil || !bytes.Equal(got, probe) {
		RestoreBackup(baseDir, backupRel, enc.DEKPath, keySetWriter(enc, baseDir))
		return fmt.Errorf("verification failed (probe did not round-trip under the target provider) — restored previous DEK (its copy %s is kept; `migrate-provider cleanup` removes it)", backupRel)
	}
	// The audit checkpoint key is KEK-derived: carry the audit verification
	// state over to the target provider's key (prepared before the re-wrap).
	audit.complete(verifySvc)

	// The target set just opened and round-tripped the probe: record it in the
	// key-set manifest as one generation, including the target provider's own
	// files (a fresh salt, a KMS/TPM blob, Shamir shares from shamir-split)
	// that the re-wrap's own manifest commit did not know about.
	if tks := keySetWriter(&tgtEnc, baseDir); tks != nil {
		if err := tks.CommitManifestFromDisk(keyfiles.OpRewrapDEK, presentPaths(tks.Required())...); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  the key-set manifest was not updated for the new provider (%v); the next server start adopts the new files with a warning\n", err)
		}
	}

	PrintMigrateSummary(tgtEnc, backupRel)
	return nil
}

// keySetWriter is the key-set manifest writer for enc (nil when none applies or
// the paths are unusable; the boot check reports unusable paths).
func keySetWriter(enc *config.EncryptionConfig, baseDir string) *keyfiles.SetWriter {
	ks, err := keyfiles.NewSetWriter(enc, baseDir)
	if err != nil {
		return nil
	}
	return ks
}

func presentPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// CopyFile copies baseDir/srcRel to baseDir/dstRel, both resolved and opened via
// securefiles' per-path-component O_NOFOLLOW walk (SecureOpenBeneath/SafeReadFile) so
// a symlink planted at any intermediate directory component (not just the leaf)
// between this tool starting and this copy running can't redirect the read or the
// write. The write is fsynced (file and directory) before returning. It truncates an
// existing destination in place, so migrate-provider no longer uses it for key
// material: CreateMigrateBackup makes the backup (O_EXCL) and RestoreBackup puts it
// back by rename.
func CopyFile(baseDir, srcRel, dstRel string) error {
	data, err := securefiles.SafeReadFile(baseDir, srcRel)
	if err != nil {
		return err
	}
	f, err := securefiles.SecureOpenBeneath(baseDir, dstRel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0600) // #nosec G304 -- baseDir/dstRel is operator-configured, walked via SecureOpenBeneath
	if err != nil {
		return err
	}
	// O_TRUNC keeps a pre-existing destination's mode untouched — the 0600 passed to
	// OpenFile above only applies when the file is freshly created. Without this
	// explicit Chmod, re-running migrate-provider (or RestoreBackup) against a dst
	// that already existed with a looser mode (e.g. a DEK/backup path left
	// world-readable by an older build, or created under a permissive umask) would
	// silently keep serving that looser mode to the re-wrapped/restored key material
	// (G68). Mirrors securefiles.SecureWriteFile/SecureWriteFileSync.
	if cerr := f.Chmod(0600); cerr != nil {
		_ = f.Close()
		return cerr
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
	return securefiles.SyncDir(filepath.Join(baseDir, filepath.Dir(dstRel)))
}

// migrateBackupNow and migrateBackupSuffix name a new backup. Test seams: a
// test pins the clock to show that two backups in the same instant still get
// different names.
var (
	migrateBackupNow    = time.Now
	migrateBackupSuffix = func() (string, error) {
		b := make([]byte, 4)
		if _, err := cryptorand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}
)

// migrateBackupAttempts bounds CreateMigrateBackup's retries on a name that
// already exists.
const migrateBackupAttempts = 3

// CreateMigrateBackup copies the wrapped DEK at baseDir/dekPath to a new
// "<dekPath>.migrate-backup.<unix-nanoseconds>-<random>" file and returns its
// name relative to baseDir. The file is created with O_EXCL, so it never
// truncates an existing backup: before REVIEW-ENCRYPTIONOPS-1 R1 the name had
// one-second resolution and a second migration in the same second overwrote
// the first one's backup, then removed it on its own failure path. The copy
// and its directory entry are fsynced before returning: the backup is the
// rollback target if verification fails.
func CreateMigrateBackup(baseDir, dekPath string) (string, error) {
	data, err := securefiles.SafeReadFile(baseDir, dekPath)
	if err != nil {
		return "", err
	}
	var lastErr error
	for range migrateBackupAttempts {
		suffix, err := migrateBackupSuffix()
		if err != nil {
			return "", fmt.Errorf("name the backup: %w", err)
		}
		backupRel := fmt.Sprintf("%s.migrate-backup.%d-%s", dekPath, migrateBackupNow().UnixNano(), suffix)
		err = securefiles.SecureCreateFileSync(baseDir, backupRel, data, 0600)
		if errors.Is(err, fs.ErrExist) {
			lastErr = err
			continue
		}
		if err != nil {
			return "", err
		}
		if err := securefiles.SyncDir(filepath.Join(baseDir, filepath.Dir(backupRel))); err != nil {
			return "", err
		}
		return backupRel, nil
	}
	return "", fmt.Errorf("no unused backup name after %d attempts: %w", migrateBackupAttempts, lastErr)
}

// migrateRestoreCrashHook, when non-nil, runs at each named step of
// RestoreBackup; returning true stops it there, as a crash would (no cleanup,
// no message). Test-only; nil in production.
var migrateRestoreCrashHook func(point string) bool

// RestoreBackup puts the backup back as the active wrapped DEK. It writes the
// backup's bytes to "<backupRel>.restoring" beside it (fsynced), renames that
// over dekPath (one directory, so the rename is atomic) and fsyncs the
// directory, so a crash at any point leaves dekPath either the re-wrapped DEK or
// the backup's bytes, never a torn file (REVIEW-ENCRYPTIONOPS-1 R1; it used to
// rewrite dekPath in place). The staging name keeps the migrate-backup prefix,
// so a leftover one is listed and removed by `migrate-provider cleanup`.
// Best-effort: logs to stderr if the restore itself fails so the operator can
// recover manually. ks (nil skips it) records the restored DEK in the key-set
// manifest: the re-wrap already committed the new DEK there, and an unrecorded
// rollback would make the next boot refuse the restored file as foreign.
func RestoreBackup(baseDir, backupRel, dekPath string, ks *keyfiles.SetWriter) {
	data, err := securefiles.SafeReadFile(baseDir, backupRel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ CRITICAL: failed to read DEK backup %s: %v\n  Restore it over %s manually before restarting.\n", backupRel, err, dekPath)
		return
	}
	files := map[string][]byte{filepath.Join(baseDir, dekPath): data}
	staged := true
	if err := ks.StageManifest(keyfiles.OpRewrapRollback, files); err != nil {
		staged = false
		fmt.Fprintf(os.Stderr, "⚠️  could not stage the key-set manifest before restoring the DEK backup (%v)\n", err)
	}
	pendingRel := backupRel + ".restoring"
	pendingFull := filepath.Join(baseDir, pendingRel)
	restoreFailed := func(err error) {
		_ = os.Remove(pendingFull)
		fmt.Fprintf(os.Stderr, "❌ CRITICAL: failed to restore DEK backup %s → %s: %v\n  %s is unchanged; restore the backup over it manually before restarting.\n", backupRel, dekPath, err, dekPath)
	}
	if filepath.Dir(filepath.Clean(backupRel)) != filepath.Dir(filepath.Clean(dekPath)) {
		restoreFailed(fmt.Errorf("the backup is not in the directory of the DEK, so it cannot be renamed into place atomically"))
		return
	}
	if err := securefiles.SecureWriteFileSync(baseDir, pendingRel, data, 0600); err != nil {
		restoreFailed(fmt.Errorf("write %s: %w", pendingRel, err))
		return
	}
	if hook := migrateRestoreCrashHook; hook != nil && hook("before-rename") {
		return
	}
	if err := os.Rename(pendingFull, filepath.Join(baseDir, dekPath)); err != nil {
		restoreFailed(fmt.Errorf("rename %s over %s: %w", pendingRel, dekPath, err))
		return
	}
	if err := securefiles.SyncDir(filepath.Dir(filepath.Join(baseDir, dekPath))); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  the DEK backup was restored over %s but the key directory could not be fsynced (%v); the restore may not survive a power loss before the next sync\n", dekPath, err)
	}
	if err := ks.CommitManifest(keyfiles.OpRewrapRollback, files); err != nil {
		if staged {
			fmt.Fprintf(os.Stderr, "⚠️  the DEK backup was restored but the key-set manifest was not updated (%v); the rollback is staged in it, so the next server start records it\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "❌ the DEK backup was restored but the key-set manifest %s was neither staged nor updated (%v): it still records the re-wrapped DEK, so the next server start refuses %s as not matching the manifest.\n"+
			"  Before restarting, fix the cause and re-run migrate-provider, or, once you have confirmed %s is the backup %s, remove %s so the next start adopts the current key files (with a WARN and an audit event).\n",
			ks.Path(), err, dekPath, dekPath, backupRel, ks.Path())
	}
}

func ProviderLabel(t string) string {
	if t == "" {
		return "password"
	}
	return t
}

func PrintMigrateSummary(tgt config.EncryptionConfig, backupRel string) {
	kp := tgt.KeyProvider
	fmt.Println("✅ DEK re-wrapped and verified under the new provider.")
	fmt.Printf("🗄️  Previous wrapped DEK backed up at %s.\n", backupRel)
	fmt.Println("   Its plaintext-after-unwrap is byte-identical to the DEK still in active use —")
	fmt.Println("   only the wrapping changed. Once you've confirmed the new provider works, run")
	fmt.Println("   `migrate-provider cleanup --confirm` to securely delete it")
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
		fmt.Println("      # the master passphrase has changed — update your deployment's secret store")
	}
	fmt.Println()
	fmt.Println("⚠️  Unlike a `rotate`, this changes the KEK — and with it, the compliance-")
	fmt.Println("   evidence-pack signing key (#268). Any evidence pack signed BEFORE this")
	fmt.Println("   migration will report as \"superseded key version\" (not tampered) under")
	fmt.Println("   `compliance verify` from now on; a routine `encryption rotate`")
	fmt.Println("   does NOT have this effect. Run `compliance verify` on any outstanding")
	fmt.Println("   packs before this step if you need to confirm they're still valid.")
}

// MigrateProviderCleanupWithConfig is the testable core of `encryption
// migrate-provider cleanup`: no flag parsing, an explicit baseDir instead of
// os.Getwd().
//
// It holds the exclusive key-directory lock (dek.lock) for its whole run,
// --dry-run included (REVIEW-ENCRYPTIONOPS-1 R2). The database-presence lock
// the admin tree takes is not enough: `--force` goes past it in flock mode, and
// a cleanup beside a migration whose verification then fails would delete the
// backup RestoreBackup needs, leaving the DEK wrapped under a KEK that may not
// work. migrate-provider holds dek.lock exclusively from start to finish, so it
// and cleanup now exclude each other whatever --force says. A live server
// holds dek.lock too (flock mode), so cleanup needs the server stopped, like
// every other key writer. Exclusive rather than shared: cleanup deletes files
// in the key directory, and the shared lock is only offered to an initialized
// Service, which would make cleanup need the passphrase it never needed.
func MigrateProviderCleanupWithConfig(cfg *config.Config, baseDir string, dryRun, confirm bool) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	lockSvc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := lockSvc.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("refusing to clean up migrate-backup files: %w — a live server or an in-progress migrate-provider or rotation is using this key directory, and a running migration may still need its backup to restore the DEK. Stop the server, or let the other command finish, then retry", err)
	}
	defer lockSvc.Shutdown()
	matches, err := FindMigrateBackups(baseDir, cfg.Storage.Encryption.DEKPath)
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

// FindMigrateBackups lists filenames (relative to baseDir) matching
// "<base>.migrate-backup.*" for the given DEK path, sorted for stable output.
func FindMigrateBackups(baseDir, dekPath string) ([]string, error) {
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
