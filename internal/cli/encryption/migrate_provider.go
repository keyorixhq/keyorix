// migrate_provider.go — `keyorix encryption migrate-provider`.
//
// Re-wraps the DEK under a KEK from a different provider (ADR-041) so an existing
// install can move between KEK providers — most importantly password/file/env → a
// cloud KMS — without re-encrypting any data.
//
// The actual logic lives in internal/encryptionops (docs/cli-split-inventory.md
// §7 PR 12), shared with the `keyorix-server admin encryption migrate-provider`
// subcommand. This file only parses flags into a local migrateOpts (kept
// lowercase-fielded because this package's tests build literals of it
// directly) and converts it to encryptionops.MigrateOpts at the call site.
package encryption

import (
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
)

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

	// mpNewPassphraseSource holds the byte-based sources (ADR-099) for the new
	// master passphrase when migrating TO the password provider, mirroring
	// common.PassphraseSource (which supplies the OLD passphrase via
	// masterPassphrase).
	mpNewPassphraseSource crypto.PassphraseSource
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

When migrating TO the password provider, set KEYORIX_NEW_MASTER_PASSWORD to the new
master passphrase.

Run on the server host (local storage). Requires --confirm. After it succeeds,
update storage.encryption.key_provider in your config to the target before the next
restart — the printed summary shows the exact block.`,
	RunE: runMigrateProvider,
}

// migrateProviderCleanupCmd securely deletes leftover `<dekPath>.migrate-backup.*`
// files (#198).
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

	fdFlag, fileFlag, stdinFlag := common.RegisterPassphraseFlags(
		f, &mpNewPassphraseSource, "new-", "new master passphrase (--to-type password only)")
	migrateProviderCmd.MarkFlagsMutuallyExclusive(fdFlag, fileFlag, stdinFlag)

	migrateProviderCmd.AddCommand(migrateProviderCleanupCmd)
	cf := migrateProviderCleanupCmd.Flags()
	cf.BoolVar(&mpCleanupConfirm, "confirm", false, "required acknowledgement before deleting backup files")
	cf.BoolVar(&mpCleanupDryRun, "dry-run", false, "list matching backup files without deleting them")
}

func runMigrateProviderCleanup(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	baseDir, _ := os.Getwd()
	return migrateProviderCleanupWithConfig(cfg, baseDir, mpCleanupDryRun, mpCleanupConfirm)
}

// migrateProviderCleanupWithConfig is a thin re-export of
// encryptionops.MigrateProviderCleanupWithConfig — kept as a package-local
// name because this package's tests call it directly.
func migrateProviderCleanupWithConfig(cfg *config.Config, baseDir string, dryRun, confirm bool) error {
	return encryptionops.MigrateProviderCleanupWithConfig(cfg, baseDir, dryRun, confirm)
}

// migrateOpts mirrors the --to-* flags with lowercase fields so this
// package's tests can build literals of it directly; toEncryptionOpsOpts
// converts it to encryptionops.MigrateOpts at the one call site that needs
// it, so the actual migration ALGORITHM (targetEncryptionConfig's provider
// validation, the backup/re-wrap/verify flow) exists exactly once, in
// encryptionops.
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

func (o migrateOpts) toEncryptionOpsOpts() encryptionops.MigrateOpts {
	return encryptionops.MigrateOpts{
		ToType:                 o.toType,
		ToKMSKeyID:             o.toKMSKeyID,
		ToWrappedKeyPath:       o.toWrappedKeyPath,
		ToKMSEncryptionContext: o.toKMSEncryptionContext,
		ToFilePath:             o.toFilePath,
		ToEnvVar:               o.toEnvVar,
		ToExecCommand:          o.toExecCommand,
		ToShareFiles:           o.toShareFiles,
		ToShareEnv:             o.toShareEnv,
		ToShareCommitment:      o.toShareCommitment,
		ToTPMDevice:            o.toTPMDevice,
		ToSaltPath:             o.toSaltPath,
	}
}

// targetEncryptionConfig is a thin re-export of
// encryptionops.TargetEncryptionConfig — kept as a package-local name because
// this package's tests call it directly.
func targetEncryptionConfig(cur *config.EncryptionConfig, opts migrateOpts) (config.EncryptionConfig, error) {
	return encryptionops.TargetEncryptionConfig(cur, opts.toEncryptionOpsOpts())
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

// migrateProviderWithConfig is a thin re-export of
// encryptionops.MigrateProviderWithConfig — kept as a package-local name
// because this package's tests call it directly.
func migrateProviderWithConfig(cfg *config.Config, opts migrateOpts, confirm bool) error {
	return encryptionops.MigrateProviderWithConfig(cfg, opts.toEncryptionOpsOpts(), confirm, common.PassphraseSource, mpNewPassphraseSource)
}

// copyFile is a thin re-export of encryptionops.CopyFile — kept as a
// package-local name because this package's tests call it directly.
func copyFile(baseDir, srcRel, dstRel string) error {
	return encryptionops.CopyFile(baseDir, srcRel, dstRel)
}

// newMasterPasswordEnv, findMigrateBackups, restoreBackup, targetPassphrase,
// providerLabel, and printMigrateSummary are thin re-exports of their
// internal/encryptionops equivalents — kept as package-local names because
// this package's tests reference them directly.
const newMasterPasswordEnv = encryptionops.NewMasterPassphraseEnvVar

func findMigrateBackups(baseDir, dekPath string) ([]string, error) {
	return encryptionops.FindMigrateBackups(baseDir, dekPath)
}

func restoreBackup(baseDir, backupRel, dekPath string) {
	encryptionops.RestoreBackup(baseDir, backupRel, dekPath)
}

func targetPassphrase(providerType string, src crypto.PassphraseSource) (string, error) {
	return encryptionops.TargetPassphrase(providerType, src)
}

func providerLabel(t string) string {
	return encryptionops.ProviderLabel(t)
}

func printMigrateSummary(tgt config.EncryptionConfig, backupRel string) {
	encryptionops.PrintMigrateSummary(tgt, backupRel)
}
