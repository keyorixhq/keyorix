// encryption.go implements `keyorix-server admin encryption <cmd>` (ADR-108
// §B3, PR 12): the 15 `encryption` family operations — KEK/DEK
// initialization, rotation, provider migration, and authentication-data
// encryption — ported from internal/cli/encryption onto this host-side admin
// tree. Every command's actual logic lives in internal/encryptionops
// (docs/cli-split-inventory.md §7 PR 12), shared with the old CLI so the
// operations exist exactly once; this file only wires cobra flags and this
// package's AcquireExclusive/audit-chain conventions on top of them.
//
// Locking: every STATE-CHANGING command here holds serverguard.AcquireExclusive
// (this package's own DB-presence/admin-single-instance guard, see admin.go)
// for its WHOLE run, in addition to whatever finer-grained key-directory lock
// (encryption.Service's own shared/exclusive lock) the underlying
// encryptionops function takes internally — the two guards are independent
// and complementary. Read-only commands (status/validate) do NOT take the
// serverguard lock, and say so in their help text, but still take the
// finer-grained shared key lock via their encryptionops function, unchanged
// from the old CLI's behavior. shamir-split touches no database or existing
// key files at all (it generates an unrelated, brand-new KEK) and so takes
// neither lock.
package admin

import (
	"os"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
)

// encPassphraseSource holds --passphrase-fd/--passphrase-file/--passphrase-stdin
// for the CURRENT master passphrase, registered as a persistent flag on
// encryptionCmd so every subcommand under it inherits the same three flags
// (mirroring internal/cli/main.go's root-level common.PassphraseSource, but
// scoped to just this subtree rather than the whole admin command).
var encPassphraseSource crypto.PassphraseSource

var encryptionCmd = &cobra.Command{
	Use:   "encryption",
	Short: "Manage encryption keys and authentication-data encryption",
	Long: `keyorix-server admin encryption -- KEK/DEK initialization, rotation, and
key-provider migration (ADR-108 §B3). Every state-changing command here holds
this admin tree's exclusive database-presence lock for its whole run (refuses
to run alongside a live server or another admin command); read-only commands
(status, validate) do not, and say so in their own help text.`,
}

func init() {
	rootCmd.AddCommand(encryptionCmd)
	fdFlag, fileFlag, stdinFlag := crypto.RegisterPassphraseFlags(
		encryptionCmd.PersistentFlags(), &encPassphraseSource, "", "master passphrase")
	encryptionCmd.MarkFlagsMutuallyExclusive(fdFlag, fileFlag, stdinFlag)

	encryptionCmd.AddCommand(encInitCmd)
	encryptionCmd.AddCommand(encStatusCmd)
	encryptionCmd.AddCommand(encRotateCmd)
	encryptionCmd.AddCommand(encUpgradeAADCmd)
	encryptionCmd.AddCommand(encValidateCmd)
	encryptionCmd.AddCommand(encFixPermsCmd)
	encryptionCmd.AddCommand(encShamirSplitCmd)
	encryptionCmd.AddCommand(encRotateKEKCmd)
	encryptionCmd.AddCommand(encMigrateProviderCmd)
	encryptionCmd.AddCommand(authEncryptionCmd) // auth_encryption.go
}

var encInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize encryption keys",
	Long:  "Generate new encryption keys (KEK and DEK) if they don't exist. Holds this tree's exclusive database-presence lock for its whole run.",
	RunE:  runEncInit,
}

func runEncInit(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.InitWithConfig(cfg, encPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.init", "ran `keyorix-server admin encryption init`", true)
	return nil
}

var encStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show encryption status",
	Long:  "Display current encryption configuration and key status. Read-only: does NOT take this tree's exclusive database-presence lock.",
	RunE:  runEncStatus,
}

func runEncStatus(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.StatusWithConfig(cfg, encPassphraseSource)
}

var (
	encRotateConfirm bool
	encRotateDryRun  bool
)

var encRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the data encryption key (DEK) with full re-encryption sweep",
	Long: `Rotate the data encryption key and re-encrypt every DEK-encrypted row in
the database within a single transaction (ADR-010). Holds this tree's
exclusive database-presence lock for its whole run, in addition to the
key-directory exclusive lock RotateDEKWithSweep takes internally.

Requires --confirm. Pass --dry-run to preview which tables/rows a rotation
would re-encrypt WITHOUT making any changes to the database or the DEK — no
--confirm needed for a dry run.

Crash safety: a kill at any point during a rotation leaves exactly one of the
old or new DEK consistently active and every row decryptable under it — never
a half-rotated database (see internal/encryptionops.RotateWithConfig's doc
comment for the mechanism).`,
	RunE: runEncRotate,
}

func init() {
	encRotateCmd.Flags().BoolVar(&encRotateConfirm, "confirm", false,
		"required acknowledgement that the database will be write-locked during the sweep")
	encRotateCmd.Flags().BoolVar(&encRotateDryRun, "dry-run", false,
		"preview which tables/rows a rotation would re-encrypt, without making any changes (does not require --confirm)")
}

func runEncRotate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.RotateWithConfig(cfg, encRotateConfirm, encRotateDryRun, encPassphraseSource); err != nil {
		return err
	}
	if encRotateDryRun {
		return nil
	}
	recordAdminAction(cfg, "admin.encryption.rotate", "ran `keyorix-server admin encryption rotate` (full DEK re-encryption sweep)", true)
	return nil
}

var encUpgradeAADCmd = &cobra.Command{
	Use:   "upgrade-aad",
	Short: "Bind legacy auth-secret rows to per-row AAD, without rotating the DEK",
	Long: `Re-encrypt every legacy (pre-#94), no-AAD row in mfa_secrets,
dynamic_secret_configs, and dynamic_secret_leases under the CURRENT DEK,
binding each to Additional Authenticated Data derived from its own identity.
Does NOT change the DEK — safe to run repeatedly, no --confirm required. Holds
this tree's exclusive database-presence lock for its whole run.`,
	RunE: runEncUpgradeAAD,
}

func runEncUpgradeAAD(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.UpgradeAADWithConfig(cfg, encPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.upgrade_aad", "ran `keyorix-server admin encryption upgrade-aad`", true)
	return nil
}

var encValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate encryption setup",
	Long:  "Check encryption configuration and key file permissions. Read-only: does NOT take this tree's exclusive database-presence lock.",
	RunE:  runEncValidate,
}

func runEncValidate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.ValidateWithConfig(cfg, encPassphraseSource)
}

var encFixPermsCmd = &cobra.Command{
	Use:   "fix-perms",
	Short: "Fix key file permissions",
	Long:  "Automatically fix permissions on encryption key files. Holds this tree's exclusive database-presence lock for its whole run.",
	RunE:  runEncFixPerms,
}

func runEncFixPerms(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.FixPermsWithConfig(cfg, encPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.fix_perms", "ran `keyorix-server admin encryption fix-perms`", true)
	return nil
}

var (
	encSSShares    int
	encSSThreshold int
	encSSOutDir    string
)

var encShamirSplitCmd = &cobra.Command{
	Use:   "shamir-split",
	Short: "Generate a new KEK split into K-of-N Shamir shares",
	Long: `Generate a fresh random 32-byte key-encryption key (KEK) and split it into N
Shamir shares (ADR-038). Touches no database or existing key files at all —
does NOT take this tree's exclusive database-presence lock.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return encryptionops.ShamirSplitWithConfig(encSSShares, encSSThreshold, encSSOutDir)
	},
}

func init() {
	f := encShamirSplitCmd.Flags()
	f.IntVar(&encSSShares, "shares", 5, "total number of shares to generate (N)")
	f.IntVar(&encSSThreshold, "threshold", 3, "shares required to reconstruct the KEK (K)")
	f.StringVar(&encSSOutDir, "out-dir", "", "write shares to this directory as share-N.hex (default: print to stdout)")
}

var (
	encRotateKEKConfirm             bool
	encRotateKEKNewPassphraseSource crypto.PassphraseSource
)

var encRotateKEKCmd = &cobra.Command{
	Use:   "rotate-kek",
	Short: "Change the master passphrase (re-wraps DEK, no database re-encryption)",
	Long: `Derives a new KEK from a new master passphrase and re-wraps the existing DEK
under it. Does NOT re-encrypt any database rows. Holds this tree's exclusive
database-presence lock for its whole run.

Crash safety: a kill mid-write leaves either the old or the fully-written new
wrapped-DEK file on disk, never a torn one — the database stays readable under
whichever passphrase matches whichever file survived.`,
	RunE: runEncRotateKEK,
}

func init() {
	encRotateKEKCmd.Flags().BoolVar(&encRotateKEKConfirm, "confirm", false,
		"required acknowledgement that the master passphrase will be changed")
	fdFlag, fileFlag, stdinFlag := crypto.RegisterPassphraseFlags(
		encRotateKEKCmd.Flags(), &encRotateKEKNewPassphraseSource, "new-", "new master passphrase")
	encRotateKEKCmd.MarkFlagsMutuallyExclusive(fdFlag, fileFlag, stdinFlag)
}

func runEncRotateKEK(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.RotateKEKWithConfig(cfg, encRotateKEKConfirm, encPassphraseSource, encRotateKEKNewPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.rotate_kek", "ran `keyorix-server admin encryption rotate-kek`", true)
	return nil
}

var (
	encMPToType                 string
	encMPToKMSKeyID             string
	encMPToWrappedKeyPath       string
	encMPToKMSEncryptionContext map[string]string
	encMPToFilePath             string
	encMPToEnvVar               string
	encMPToExecCommand          []string
	encMPToShareFiles           []string
	encMPToShareEnv             []string
	encMPToShareCommitment      string
	encMPToTPMDevice            string
	encMPToSaltPath             string
	encMPConfirm                bool
	encMPNewPassphraseSource    crypto.PassphraseSource

	encMPCleanupConfirm bool
	encMPCleanupDryRun  bool
)

var encMigrateProviderCmd = &cobra.Command{
	Use:   "migrate-provider",
	Short: "Migrate the KEK to a different key provider without re-encrypting data",
	Long: `Re-wrap the DEK with a KEK from a different provider (ADR-041) — e.g. move an
existing install from a password-derived KEK to a cloud KMS. Only the DEK's
wrapping changes; secret values are never re-encrypted. Requires --confirm.
Holds this tree's exclusive database-presence lock for its whole run.

Crash safety: the previous wrapped DEK is backed up (durably, fsynced) BEFORE
the re-wrap; a kill before the re-wrap leaves the old wrapped DEK untouched
and re-running is safe. A kill after the re-wrap but before this command's own
verification completes leaves the backup on disk for a human to restore
manually — the DEK's plaintext value is unchanged either way, so no data is
ever at risk of becoming undecryptable.`,
	RunE: runEncMigrateProvider,
}

var encMigrateProviderCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Securely delete leftover pre-migration wrapped-DEK backups",
	Long: `Find and securely delete every "<dek_path>.migrate-backup.*" file left behind
by a previous migrate-provider run. Requires --confirm; use --dry-run to
preview first. Holds this tree's exclusive database-presence lock for its
whole run — a narrow TOCTOU against a concurrent migrate-provider run is
theoretically possible without it (docs/cli-split-inventory.md §2.4).`,
	RunE: runEncMigrateProviderCleanup,
}

func init() {
	f := encMigrateProviderCmd.Flags()
	f.StringVar(&encMPToType, "to-type", "", "target provider: password|file|env|exec|shamir|tpm|aws-kms|gcp-kms|azure-kms (required)")
	f.StringVar(&encMPToKMSKeyID, "to-kms-key-id", "", "target KMS key id/ARN/resource-name/URL (kms types)")
	f.StringVar(&encMPToWrappedKeyPath, "to-wrapped-key-path", "", "where to store the KMS-wrapped KEK blob (kms types)")
	f.StringToStringVar(&encMPToKMSEncryptionContext, "to-kms-encryption-context", nil,
		"encryption context/AAD binding the wrapped KEK to this install (aws-kms/gcp-kms only)")
	f.StringVar(&encMPToFilePath, "to-file-path", "", "path to the raw KEK material (file type)")
	f.StringVar(&encMPToEnvVar, "to-env-var", "", "env var holding the raw KEK (env type)")
	f.StringSliceVar(&encMPToExecCommand, "to-exec-command", nil, "resolver argv whose stdout supplies the KEK (exec type)")
	f.StringSliceVar(&encMPToShareFiles, "to-shamir-share-files", nil, "paths to >=threshold Shamir share files (shamir type)")
	f.StringSliceVar(&encMPToShareEnv, "to-shamir-share-env", nil, "env var names holding Shamir shares (shamir type)")
	f.StringVar(&encMPToShareCommitment, "to-shamir-commitment", "", "hex KEK commitment printed by `shamir-split` for these shares")
	f.StringVar(&encMPToTPMDevice, "to-tpm-device", "", "TPM 2.0 device path (tpm type; default /dev/tpmrm0)")
	f.StringVar(&encMPToSaltPath, "to-salt-path", "", "salt path for the target password provider (default: current salt_path)")
	f.BoolVar(&encMPConfirm, "confirm", false, "required acknowledgement before re-wrapping the DEK")
	fdFlag, fileFlag, stdinFlag := crypto.RegisterPassphraseFlags(
		f, &encMPNewPassphraseSource, "new-", "new master passphrase (--to-type password only)")
	encMigrateProviderCmd.MarkFlagsMutuallyExclusive(fdFlag, fileFlag, stdinFlag)

	encMigrateProviderCmd.AddCommand(encMigrateProviderCleanupCmd)
	cf := encMigrateProviderCleanupCmd.Flags()
	cf.BoolVar(&encMPCleanupConfirm, "confirm", false, "required acknowledgement before deleting backup files")
	cf.BoolVar(&encMPCleanupDryRun, "dry-run", false, "list matching backup files without deleting them")
}

func runEncMigrateProvider(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	opts := encryptionops.MigrateOpts{
		ToType:                 encMPToType,
		ToKMSKeyID:             encMPToKMSKeyID,
		ToWrappedKeyPath:       encMPToWrappedKeyPath,
		ToKMSEncryptionContext: encMPToKMSEncryptionContext,
		ToFilePath:             encMPToFilePath,
		ToEnvVar:               encMPToEnvVar,
		ToExecCommand:          encMPToExecCommand,
		ToShareFiles:           encMPToShareFiles,
		ToShareEnv:             encMPToShareEnv,
		ToShareCommitment:      encMPToShareCommitment,
		ToTPMDevice:            encMPToTPMDevice,
		ToSaltPath:             encMPToSaltPath,
	}
	if err := encryptionops.MigrateProviderWithConfig(cfg, opts, encMPConfirm, encPassphraseSource, encMPNewPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.migrate_provider", "ran `keyorix-server admin encryption migrate-provider` (target: "+encMPToType+")", true)
	return nil
}

func runEncMigrateProviderCleanup(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	baseDir, _ := os.Getwd()
	if err := encryptionops.MigrateProviderCleanupWithConfig(cfg, baseDir, encMPCleanupDryRun, encMPCleanupConfirm); err != nil {
		return err
	}
	if encMPCleanupDryRun {
		return nil
	}
	recordAdminAction(cfg, "admin.encryption.migrate_provider_cleanup", "ran `keyorix-server admin encryption migrate-provider cleanup`", true)
	return nil
}
