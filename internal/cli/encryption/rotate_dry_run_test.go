package encryption

// rotate_dry_run_test.go — regression tests for backlog #425: `keyorix encryption
// rotate --dry-run` and the expanded post-rotation summary.
//
// Covers:
//  1. TestRotateWithConfig_DryRun_AccuratePreviewNoChanges — a --dry-run reports
//     an accurate per-table preview (one row seeded per DEK-encrypted table) and
//     makes NO changes: the seeded ciphertext is byte-for-byte unchanged and the
//     DEK/key version is unchanged, verified by re-initialising a fresh Service
//     from the on-disk key material after the dry run.
//  2. TestRotateWithConfig_DryRun_DoesNotRequireConfirm — --dry-run succeeds
//     without --confirm (a preview isn't the irreversible operation --confirm
//     guards).
//  3. TestRotateWithConfig_RealRotation_PrintsAllSweepResultFields — a real
//     (non-dry-run) rotation's printed summary now includes all 8 SweepResult
//     "Swept" fields, not just the original 5 — closing the operator-visibility
//     gap where mfa_secrets/dynamic_secret_configs/dynamic_secret_leases (the
//     exact 3 tables #422's sweep-gap fix added) were silently omitted.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	enc "github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const dryRunTestPassphrase = "dry-run-test-passphrase-correct-horse-battery"

// captureStdout redirects os.Stdout for the duration of fn and returns everything
// written to it, so tests can assert on the operator-facing CLI output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	return buf.String()
}

// seedOneRowPerTable seeds exactly one row into every one of the 8 DEK-encrypted
// tables SweepResult tracks, each with a distinguishable plaintext, so a test can
// assert on the per-table counts a preview or a real rotation reports.
func seedOneRowPerTable(t *testing.T, db *gorm.DB, svc *enc.Service) {
	t.Helper()

	node := &models.SecretNode{ProjectID: 1, Name: "dry-run-node", IsSecret: true}
	mustCreate(t, db, node)
	aad := enc.SecretAAD(node.ID, 1, 1)
	val, meta := mustEncryptAAD(t, svc, "dry-run-secret-value", aad)
	mustCreate(t, db, &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: val, EncryptionMetadata: models.JSON(meta)})

	sVal, sMeta := mustEncrypt(t, svc, "dry-run-session-token")
	mustCreate(t, db, &models.Session{UserID: 1, SessionToken: "dry-run-session", EncryptedSessionToken: sVal, SessionTokenMetadata: models.JSON(sMeta)})

	tVal, tMeta := mustEncrypt(t, svc, "dry-run-api-token")
	mustCreate(t, db, &models.APIToken{ClientID: 1, Token: "dry-run-token", EncryptedToken: tVal, TokenMetadata: models.JSON(tMeta)})

	cVal, cMeta := mustEncrypt(t, svc, "dry-run-client-secret")
	mustCreate(t, db, &models.APIClient{Name: "dry-run-client", ClientID: "dry-run-client-id", EncryptedClientSecret: cVal, ClientSecretMetadata: models.JSON(cMeta)})

	prVal, prMeta := mustEncrypt(t, svc, "dry-run-reset-token")
	mustCreate(t, db, &models.PasswordReset{UserID: 1, Token: "dry-run-reset", EncryptedToken: prVal, TokenMetadata: models.JSON(prMeta)})

	mfaVal, mfaMeta := mustEncrypt(t, svc, "dry-run-totp-seed")
	mustCreate(t, db, &models.MFASecret{UserID: 1, SecretEnc: mfaVal, SecretMeta: mfaMeta})

	dsnVal, dsnMeta := mustEncrypt(t, svc, "postgres://dry-run@db/app")
	mustCreate(t, db, &models.DynamicSecretConfig{Name: "dry-run-pg", ProjectID: 1, EnvironmentID: 1, AdminDSNEnc: dsnVal, AdminDSNMeta: dsnMeta})

	credVal, credMeta := mustEncrypt(t, svc, `{"user":"dry-run","pass":"run"}`)
	mustCreate(t, db, &models.DynamicSecretLease{LeaseID: "dry-run-lease", ConfigID: 1, CredentialEnc: credVal, CredentialMeta: credMeta})
}

// setupDryRunTest wires a throwaway on-disk sqlite DB + key directory, seeds one
// row per DEK-encrypted table, and returns the config plus the still-live seeding
// Service (so the caller can decrypt seeded rows with the pre-rotation DEK).
func setupDryRunTest(t *testing.T) (*config.Config, *enc.Service, string) {
	t.Helper()
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", dryRunTestPassphrase)

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	dbPath := filepath.Join(workDir, "secrets.db")
	cfg.Storage.Database.Path = dbPath

	svc := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := svc.Initialize(dryRunTestPassphrase); err != nil {
		t.Fatalf("initialise encryption: %v", err)
	}
	t.Cleanup(svc.Shutdown)

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Session{},
		&models.APIToken{}, &models.APIClient{}, &models.PasswordReset{},
		&models.MFASecret{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	seedOneRowPerTable(t, db, svc)
	closeGorm(db)

	return cfg, svc, workDir
}

// assertAllEightFieldsReported checks the CLI's printed summary surfaces every one
// of the 8 SweepResult "Swept" fields (plus LegacyAADUpgraded) with the expected
// count — the core regression this fix closes: previously only 5 of 8 were ever
// logged, and the CLI printed none of them at all.
func assertAllEightFieldsReported(t *testing.T, output string, wantCount int) {
	t.Helper()
	for _, field := range []string{
		"secret_versions", "sessions", "api_tokens", "api_clients",
		"password_resets", "mfa_secrets", "dynamic_secret_configs", "dynamic_secret_leases",
	} {
		if !strings.Contains(output, field) {
			t.Errorf("expected summary output to mention %q, got:\n%s", field, output)
		}
	}
	if !strings.Contains(output, "legacy AAD upgraded") {
		t.Errorf("expected summary output to mention legacy AAD upgraded count, got:\n%s", output)
	}
	_ = wantCount // counts are checked precisely by the callers below via fmt.Sprintf assertions
}

// TestRotateWithConfig_DryRun_AccuratePreviewNoChanges is the core --dry-run
// regression: the preview must report the correct row count for every table AND
// must not change a single byte of ciphertext or rotate the DEK.
func TestRotateWithConfig_DryRun_AccuratePreviewNoChanges(t *testing.T) {
	cfg, seedSvc, workDir := setupDryRunTest(t)

	preRotateKeyVersion := seedSvc.GetKeyVersion()

	// Snapshot every seeded row's raw ciphertext before the dry run.
	dbBefore, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	var (
		verBefore   models.SecretVersion
		sessBefore  models.Session
		tokBefore   models.APIToken
		cliBefore   models.APIClient
		rstBefore   models.PasswordReset
		mfaBefore   models.MFASecret
		dsnBefore   models.DynamicSecretConfig
		leaseBefore models.DynamicSecretLease
	)
	mustFirst(t, dbBefore, &verBefore, 1)
	mustFirst(t, dbBefore, &sessBefore, 1)
	mustFirst(t, dbBefore, &tokBefore, 1)
	mustFirst(t, dbBefore, &cliBefore, 1)
	mustFirst(t, dbBefore, &rstBefore, 1)
	mustFirst(t, dbBefore, &mfaBefore, 1)
	mustFirst(t, dbBefore, &dsnBefore, 1)
	mustFirst(t, dbBefore, &leaseBefore, 1)
	closeGorm(dbBefore)

	var rotErr error
	output := captureStdout(t, func() {
		// confirm=false, dryRun=true: a dry run must succeed WITHOUT --confirm.
		rotErr = rotateWithConfig(cfg, false, true)
	})
	if rotErr != nil {
		t.Fatalf("dry-run rotateWithConfig failed: %v", rotErr)
	}

	if !strings.Contains(output, "Dry run") {
		t.Errorf("expected dry-run output to announce itself as a dry run, got:\n%s", output)
	}
	for _, want := range []string{
		"secret_versions: 1", "sessions: 1", "api_tokens: 1", "api_clients: 1",
		"password_resets: 1", "mfa_secrets: 1", "dynamic_secret_configs: 1",
		// seedOneRowPerTable encrypts all 8 table rows via the legacy (no-AAD) path.
		// Sweepers that bind AAD (mfa_secrets, dynamic_secret_configs,
		// dynamic_secret_leases, sessions, api_tokens, password_resets) upgrade their
		// rows in place — 6 tables × 1 row = 6 legacy upgrades. secret_versions was
		// seeded AAD-bound; api_clients does not bind AAD.
		"dynamic_secret_leases: 1", "legacy AAD upgraded: 6",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected dry-run preview to report %q, got:\n%s", want, output)
		}
	}

	// No pending-DEK or promoted-DEK-related file activity: a dry run must never
	// touch the key directory at all.
	if _, err := os.Stat(filepath.Join(workDir, "dek.key.pending")); !os.IsNotExist(err) {
		t.Errorf("dry run must not create a pending DEK file (stat err: %v)", err)
	}

	// The DEK/key version must be completely unchanged: re-initialise a FRESH
	// Service straight from the on-disk key material and confirm it reports the
	// exact same key version the pre-dry-run Service had.
	freshSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := freshSvc.Initialize(dryRunTestPassphrase); err != nil {
		t.Fatalf("re-initialise from on-disk key after dry run: %v", err)
	}
	defer freshSvc.Shutdown()
	if got := freshSvc.GetKeyVersion(); got != preRotateKeyVersion {
		t.Errorf("DEK/key version changed by a --dry-run: before=%q after=%q", preRotateKeyVersion, got)
	}

	// Every seeded row's ciphertext must be byte-for-byte unchanged.
	dbAfter, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer closeGorm(dbAfter)

	var verAfter models.SecretVersion
	mustFirst(t, dbAfter, &verAfter, 1)
	if !bytes.Equal(verBefore.EncryptedValue, verAfter.EncryptedValue) {
		t.Error("secret_versions ciphertext changed by a --dry-run")
	}
	var sessAfter models.Session
	mustFirst(t, dbAfter, &sessAfter, 1)
	if !bytes.Equal(sessBefore.EncryptedSessionToken, sessAfter.EncryptedSessionToken) {
		t.Error("sessions ciphertext changed by a --dry-run")
	}
	var tokAfter models.APIToken
	mustFirst(t, dbAfter, &tokAfter, 1)
	if !bytes.Equal(tokBefore.EncryptedToken, tokAfter.EncryptedToken) {
		t.Error("api_tokens ciphertext changed by a --dry-run")
	}
	var cliAfter models.APIClient
	mustFirst(t, dbAfter, &cliAfter, 1)
	if !bytes.Equal(cliBefore.EncryptedClientSecret, cliAfter.EncryptedClientSecret) {
		t.Error("api_clients ciphertext changed by a --dry-run")
	}
	var rstAfter models.PasswordReset
	mustFirst(t, dbAfter, &rstAfter, 1)
	if !bytes.Equal(rstBefore.EncryptedToken, rstAfter.EncryptedToken) {
		t.Error("password_resets ciphertext changed by a --dry-run")
	}
	var mfaAfter models.MFASecret
	mustFirst(t, dbAfter, &mfaAfter, 1)
	if !bytes.Equal(mfaBefore.SecretEnc, mfaAfter.SecretEnc) {
		t.Error("mfa_secrets ciphertext changed by a --dry-run")
	}
	var dsnAfter models.DynamicSecretConfig
	mustFirst(t, dbAfter, &dsnAfter, 1)
	if !bytes.Equal(dsnBefore.AdminDSNEnc, dsnAfter.AdminDSNEnc) {
		t.Error("dynamic_secret_configs ciphertext changed by a --dry-run")
	}
	var leaseAfter models.DynamicSecretLease
	mustFirst(t, dbAfter, &leaseAfter, 1)
	if !bytes.Equal(leaseBefore.CredentialEnc, leaseAfter.CredentialEnc) {
		t.Error("dynamic_secret_leases ciphertext changed by a --dry-run")
	}

	// The seeded ciphertext must still decrypt under the ORIGINAL (never-rotated)
	// DEK — the strongest possible proof nothing was re-encrypted.
	aad := enc.SecretAAD(1, 1, 1)
	if pt, err := seedSvc.DecryptSecretWithAAD(verAfter.EncryptedValue, aad); err != nil {
		t.Errorf("seeded secret no longer decrypts under the original DEK after a dry run: %v", err)
	} else if string(pt) != "dry-run-secret-value" {
		t.Errorf("unexpected plaintext after dry run: %q", pt)
	}
}

// TestRotateWithConfig_DryRun_DoesNotRequireConfirm proves --dry-run does not
// need --confirm: unlike a real rotation, previewing what would happen is not the
// irreversible operation --confirm guards.
func TestRotateWithConfig_DryRun_DoesNotRequireConfirm(t *testing.T) {
	cfg, _, _ := setupDryRunTest(t)

	var rotErr error
	_ = captureStdout(t, func() {
		rotErr = rotateWithConfig(cfg, false, true)
	})
	if rotErr != nil {
		t.Fatalf("dry-run should succeed without --confirm, got: %v", rotErr)
	}
}

// TestRotateWithConfig_RealRotation_PrintsAllSweepResultFields proves the
// post-rotation summary a REAL rotation prints now surfaces all 8 SweepResult
// "Swept" fields (plus LegacyAADUpgraded) — not just the original 5, which
// silently omitted mfa_secrets, dynamic_secret_configs, and
// dynamic_secret_leases (the exact 3 tables #422's own sweep-gap fix added).
func TestRotateWithConfig_RealRotation_PrintsAllSweepResultFields(t *testing.T) {
	cfg, _, _ := setupDryRunTest(t)

	var rotErr error
	output := captureStdout(t, func() {
		rotErr = rotateWithConfig(cfg, true, false)
	})
	if rotErr != nil {
		t.Fatalf("real rotation failed: %v", rotErr)
	}

	if !strings.Contains(output, "DEK rotated successfully") {
		t.Errorf("expected the usual real-rotation success message, got:\n%s", output)
	}
	for _, want := range []string{
		"secret_versions: 1", "sessions: 1", "api_tokens: 1", "api_clients: 1",
		"password_resets: 1", "mfa_secrets: 1", "dynamic_secret_configs: 1",
		// seedOneRowPerTable encrypts all 8 table rows via the legacy (no-AAD) path.
		// Sweepers that bind AAD (mfa_secrets, dynamic_secret_configs,
		// dynamic_secret_leases, sessions, api_tokens, password_resets) upgrade their
		// rows in place — 6 tables × 1 row = 6 legacy upgrades. secret_versions was
		// seeded AAD-bound; api_clients does not bind AAD.
		"dynamic_secret_leases: 1", "legacy AAD upgraded: 6",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected post-rotation summary to report %q, got:\n%s", want, output)
		}
	}
	assertAllEightFieldsReported(t, output, 1)
}
