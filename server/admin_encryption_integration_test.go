package main

// admin_encryption_integration_test.go exercises `keyorix-server admin
// encryption <cmd>` as a real subprocess against the built binary (ADR-108
// §B3, PR 12) -- the same build-then-exec pattern
// admin_integration_test.go uses for the B1 subcommands. Covers the full
// 15-command family against a temp SQLite database: init, status, rotate
// (dry-run and --confirm), upgrade-aad, validate, fix-perms, shamir-split,
// rotate-kek, migrate-provider (+cleanup), and the auth-encryption
// status/enable/migrate/validate/rotate quintet -- plus the exclusive-lock
// guard (state-changing commands refuse while another admin/server holds
// it; read-only commands do not need it) and a real secret round-trip
// through a DEK rotation (data readable under the new key, not under the
// revoked old one). Postgres-backed coverage lives in
// admin_encryption_integration_postgres_test.go (gated on
// KEYORIX_TEST_PG_DSN).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// encryptionYAML writes a local-SQLite config with encryption enabled, the
// same dek_path/salt_path layout every admin-encryption test in this file
// uses.
func encryptionYAML(dir string) error {
	content := `storage:
  type: local
  database:
    path: ./secrets.db
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
`
	return os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(content), 0600)
}

// openTestSecretsDB opens dir/secrets.db directly via gorm (bypassing the
// admin binary) so the test can seed/read a SecretVersion row the same way
// the running application would -- used to prove rotate's re-encryption
// sweep actually preserves data, not just that the command exits 0.
func openTestSecretsDB(t *testing.T, dir string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "secrets.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open secrets.db directly: %v", err)
	}
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		t.Fatalf("automigrate secret tables: %v", err)
	}
	return db
}

// seedProbeSecret encrypts plaintext under a Service opened against dir with
// passphrase, and inserts a SecretVersion row -- exactly the shape rotate's
// sweep operates on. Returns the row ID and the AAD needed to decrypt it.
func seedProbeSecret(t *testing.T, dir, passphrase, plaintext string) (db *gorm.DB, versionID uint, aad []byte) {
	t.Helper()
	db = openTestSecretsDB(t, dir)
	node := &models.SecretNode{ProjectID: 1, Name: "probe-node", IsSecret: true}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("seed service Initialize: %v", err)
	}
	defer svc.Shutdown()
	aad = encryption.SecretAAD(node.ID, node.ProjectID, 1)
	enc, meta, err := svc.EncryptSecretWithAAD([]byte(plaintext), aad)
	if err != nil {
		t.Fatalf("seed EncryptSecretWithAAD: %v", err)
	}
	v := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("seed SecretVersion: %v", err)
	}
	return db, v.ID, aad
}

// decryptProbeSecret opens a FRESH Service against dir (as a restarted
// process would) and decrypts the row -- proving the row is readable under
// whatever DEK is CURRENTLY active on disk. kp describes the CURRENT key
// provider (zero value = password, the default); pass the same
// config.KeyProviderConfig a migrate-provider run switched to, once one has
// run, so this helper unwraps the DEK the same way the real config does.
func decryptProbeSecret(t *testing.T, dir, passphrase string, kp config.KeyProviderConfig, db *gorm.DB, versionID uint, aad []byte) (string, error) {
	t.Helper()
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatalf("fetch probe row: %v", err)
	}
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt", KeyProvider: kp}, dir)
	if err := svc.Initialize(passphrase); err != nil {
		return "", fmt.Errorf("Initialize: %w", err)
	}
	defer svc.Shutdown()
	pt, err := svc.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func TestAdminEncryptionWorkflow_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-sqlite"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionYAML(dir); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}

	// init: generates the KEK/DEK.
	out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption init failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keys", "dek.key")); statErr != nil {
		t.Fatalf("expected dek.key to be created: %v", statErr)
	}

	// status: read-only, must report enabled+initialized.
	out, err = runAdmin(t, bin, dir, env, "encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption status failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Initialized: ✅") {
		t.Errorf("expected status to report Initialized, got:\n%s", out)
	}

	// validate: read-only, must pass on a freshly-initialized key directory.
	out, err = runAdmin(t, bin, dir, env, "encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Encryption setup is valid") {
		t.Errorf("expected validate to pass, got:\n%s", out)
	}

	// fix-perms: state-changing but always safe to run.
	out, err = runAdmin(t, bin, dir, env, "encryption", "fix-perms", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption fix-perms failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "permissions fixed") {
		t.Errorf("expected fix-perms to report success, got:\n%s", out)
	}

	// Seed a real secret row before rotating, directly against the same
	// secrets.db the admin binary will operate on.
	db, versionID, aad := seedProbeSecret(t, dir, passphrase, "rotate-me-probe-value")

	// rotate --dry-run: must not change anything.
	out, err = runAdmin(t, bin, dir, env, "encryption", "rotate", "--dry-run", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate --dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no changes were made") {
		t.Errorf("expected dry-run to report no changes, got:\n%s", out)
	}
	if got, derr := decryptProbeSecret(t, dir, passphrase, config.KeyProviderConfig{}, db, versionID, aad); derr != nil || got != "rotate-me-probe-value" {
		t.Fatalf("probe secret unreadable or changed after dry-run: got=%q err=%v", got, derr)
	}

	// rotate --confirm: the real DEK rotation + full re-encryption sweep.
	out, err = runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate --confirm failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "DEK rotated successfully") {
		t.Errorf("expected rotate to report success, got:\n%s", out)
	}

	// Data readable under the NEW (post-rotation) key.
	got, derr := decryptProbeSecret(t, dir, passphrase, config.KeyProviderConfig{}, db, versionID, aad)
	if derr != nil {
		t.Fatalf("DATA LOSS: probe secret unreadable after rotate: %v", derr)
	}
	if got != "rotate-me-probe-value" {
		t.Fatalf("VALUE CORRUPTION: probe secret changed after rotate: got %q", got)
	}

	// upgrade-aad: safe to run repeatedly, no --confirm required.
	out, err = runAdmin(t, bin, dir, env, "encryption", "upgrade-aad", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption upgrade-aad failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "AAD upgrade complete") {
		t.Errorf("expected upgrade-aad to report success, got:\n%s", out)
	}

	// shamir-split: touches no database/existing key files.
	shareDir := filepath.Join(dir, "shares")
	if err := os.MkdirAll(shareDir, 0750); err != nil {
		t.Fatalf("mkdir shares: %v", err)
	}
	out, err = runAdmin(t, bin, dir, env, "encryption", "shamir-split", "--shares", "3", "--threshold", "2", "--out-dir", shareDir)
	if err != nil {
		t.Fatalf("encryption shamir-split failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "share-1.hex")); statErr != nil {
		t.Fatalf("expected shamir-split to write share-1.hex: %v", statErr)
	}

	// rotate-kek: changes the master passphrase, re-wraps the DEK, no DB re-encryption.
	const newPassphrase = "test-passphrase-enc-sqlite-ROTATED"
	kekEnv := append(env, "KEYORIX_NEW_MASTER_PASSWORD="+newPassphrase)
	out, err = runAdmin(t, bin, dir, kekEnv, "encryption", "rotate-kek", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate-kek failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "KEK rotation complete") {
		t.Errorf("expected rotate-kek to report success, got:\n%s", out)
	}
	// Data must still be readable under the new passphrase (KEK changed, DEK value did not).
	if got, derr := decryptProbeSecret(t, dir, newPassphrase, config.KeyProviderConfig{}, db, versionID, aad); derr != nil || got != "rotate-me-probe-value" {
		t.Fatalf("probe secret unreadable or changed after rotate-kek: got=%q err=%v", got, derr)
	}
	// And NOT readable under the old passphrase any more.
	if _, derr := decryptProbeSecret(t, dir, passphrase, config.KeyProviderConfig{}, db, versionID, aad); derr == nil {
		t.Fatalf("expected the OLD passphrase to no longer open the key directory after rotate-kek")
	}
	// Subsequent commands must authenticate with the ROTATED passphrase —
	// rebuild env from baseEnv rather than appending to the old one, so the
	// stale KEYORIX_MASTER_PASSWORD=<old passphrase> entry doesn't shadow
	// this new one (duplicate env var names is fragile to rely on).
	env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+newPassphrase)

	// migrate-provider: move to a file-based KEK provider.
	kekMaterial := make([]byte, crypto.KEKSize)
	for i := range kekMaterial {
		kekMaterial[i] = byte(i + 1)
	}
	kekFilePath := filepath.Join(dir, "external-kek.bin")
	if err := os.WriteFile(kekFilePath, kekMaterial, 0600); err != nil {
		t.Fatalf("write external KEK material: %v", err)
	}
	out, err = runAdmin(t, bin, dir, env, "encryption", "migrate-provider",
		"--to-type", "file", "--to-file-path", kekFilePath, "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption migrate-provider failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "re-wrapped and verified") {
		t.Errorf("expected migrate-provider to report success, got:\n%s", out)
	}
	// A migrate-backup file must exist next to the DEK.
	backups, _ := filepath.Glob(filepath.Join(dir, "keys", "dek.key.migrate-backup.*"))
	if len(backups) == 0 {
		t.Fatalf("expected at least one migrate-backup file after migrate-provider")
	}

	// migrate-provider re-wraps the DEK but, per its own printed summary,
	// deliberately does NOT persist the new key_provider into keyorix.yaml —
	// that is the operator's follow-up step. Do it here, exactly as the
	// summary instructs, so subsequent commands resolve the KEK the same
	// way a real post-migration deployment would.
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(fmt.Sprintf(`storage:
  type: local
  database:
    path: ./secrets.db
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
    key_provider:
      type: file
      file_path: %s
`, kekFilePath)), 0600); err != nil {
		t.Fatalf("update config after migrate-provider: %v", err)
	}

	// migrate-provider cleanup --dry-run: lists, does not delete.
	out, err = runAdmin(t, bin, dir, env, "encryption", "migrate-provider", "cleanup", "--dry-run", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption migrate-provider cleanup --dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no files deleted") {
		t.Errorf("expected cleanup --dry-run to not delete, got:\n%s", out)
	}
	if _, statErr := os.Stat(backups[0]); statErr != nil {
		t.Fatalf("expected backup file to survive --dry-run cleanup: %v", statErr)
	}

	// migrate-provider cleanup --confirm: actually deletes.
	out, err = runAdmin(t, bin, dir, env, "encryption", "migrate-provider", "cleanup", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption migrate-provider cleanup --confirm failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Securely deleted") {
		t.Errorf("expected cleanup --confirm to report deletion, got:\n%s", out)
	}
	if _, statErr := os.Stat(backups[0]); statErr == nil {
		t.Fatalf("expected backup file to be deleted after cleanup --confirm")
	}

	// --- auth-encryption family ---

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption status failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Authentication Encryption Status") {
		t.Errorf("expected auth-encryption status header, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "enable", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption enable failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "migration completed successfully") {
		t.Errorf("expected auth-encryption migrate to report success, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "validation checks passed") {
		t.Errorf("expected auth-encryption validate to pass, got:\n%s", out)
	}

	// auth-encryption rotate: S13's fix point — a true DEK rotation. Must
	// still preserve the probe secret (RotateDEKWithSweep covers every
	// DEK-encrypted table, not just auth ones).
	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption rotate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "rotation completed successfully") {
		t.Errorf("expected auth-encryption rotate to report success, got:\n%s", out)
	}
	// The KEK provider is "file" since migrate-provider above — no passphrase
	// is needed or used to unwrap it (mirrors encryptionops.MasterPassphrase's
	// own "" for a non-password provider).
	fileProvider := config.KeyProviderConfig{Type: "file", FilePath: kekFilePath}
	if got, derr := decryptProbeSecret(t, dir, "", fileProvider, db, versionID, aad); derr != nil || got != "rotate-me-probe-value" {
		t.Fatalf("probe secret unreadable or changed after auth-encryption rotate: got=%q err=%v", got, derr)
	}

	// auth-encryption rotate without --confirm must be refused.
	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "rotate", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "--confirm") {
		t.Fatalf("expected auth-encryption rotate without --confirm to be refused, got (err=%v):\n%s", err, out)
	}
}

// TestAdminEncryptionRotate_RefusedWhileExclusiveLockHeld_SQLite confirms the
// task-2 requirement: every STATE-CHANGING encryption command holds this
// tree's exclusive database-presence lock for its whole run, so it refuses
// to run while another admin command (or a live server) already holds it.
func TestAdminEncryptionRotate_RefusedWhileExclusiveLockHeld_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-lock-sqlite"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionYAML(dir); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	if out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("encryption init failed: %v\n%s", err, out)
	}

	hook := startLockHolderHook(t, bin, dir, env)
	defer hook.release(t)

	out, err := runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("expected encryption rotate to refuse while the exclusive lock is held, got (err=%v):\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "fix-perms", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("expected encryption fix-perms to refuse while the exclusive lock is held, got (err=%v):\n%s", err, out)
	}
}

// TestAdminEncryptionStatus_DoesNotRequireExclusiveLock_SQLite confirms the
// task-2 exception: read-only commands (status, validate) do NOT take the
// exclusive database-presence lock, so they succeed even while another
// admin command holds it.
func TestAdminEncryptionStatus_DoesNotRequireExclusiveLock_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-readonly-sqlite"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionYAML(dir); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	if out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("encryption init failed: %v\n%s", err, out)
	}

	hook := startLockHolderHook(t, bin, dir, env)
	defer hook.release(t)

	out, err := runAdmin(t, bin, dir, env, "encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("expected encryption status to succeed while the exclusive lock is held (read-only), got (err=%v):\n%s", err, out)
	}
	if strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("encryption status must not take the exclusive database-presence lock, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("expected encryption validate to succeed while the exclusive lock is held (read-only), got (err=%v):\n%s", err, out)
	}
	if strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("encryption validate must not take the exclusive database-presence lock, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("expected auth-encryption status to succeed while the exclusive lock is held (read-only), got (err=%v):\n%s", err, out)
	}
	if strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("auth-encryption status must not take the exclusive database-presence lock, got:\n%s", out)
	}
}
