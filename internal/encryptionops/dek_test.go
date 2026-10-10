package encryptionops

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- MasterPassphrase -------------------------------------------------

func TestMasterPassphrase_PasswordProvider_ReadsEnvFallback(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)

	got, err := MasterPassphrase(cfg, zeroPassSrc())
	if err != nil {
		t.Fatalf("MasterPassphrase: %v", err)
	}
	if got != testBaselinePassphrase {
		t.Fatalf("got %q, want %q", got, testBaselinePassphrase)
	}
}

func TestMasterPassphrase_PasswordProvider_MissingEverywhereErrors(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	// Deliberately do not set the env var.
	if _, err := MasterPassphrase(cfg, zeroPassSrc()); err == nil {
		t.Fatal("expected an error when no passphrase source is configured, got nil")
	}
}

func TestMasterPassphrase_NonPasswordProvider_ReturnsEmptyNoError(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	cfg.Storage.Encryption.KeyProvider.Type = "file"
	// No env var set — must NOT be consulted for a non-password provider.
	got, err := MasterPassphrase(cfg, zeroPassSrc())
	if err != nil {
		t.Fatalf("MasterPassphrase: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty passphrase for a non-password provider, got %q", got)
	}
}

// --- InitWithConfig -----------------------------------------------------

func TestInitWithConfig_Disabled_NoError(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("expected nil error when encryption disabled, got %v", err)
	}
	if _, err := os.Stat("dek.key"); err == nil {
		t.Fatal("dek.key must not be created when encryption is disabled")
	}
}

func TestInitWithConfig_CreatesKeyFilesWithRestrictivePerms(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("InitWithConfig: %v", err)
	}
	if mode := fileMode(t, "dek.key"); mode&0o077 != 0 {
		t.Fatalf("dek.key must not be group/world accessible, got mode %v", mode)
	}
	if mode := fileMode(t, "kek.salt"); mode&0o077 != 0 {
		t.Fatalf("kek.salt must not be group/world accessible, got mode %v", mode)
	}
}

// --- RotateWithConfig: validation gates ---------------------------------

func TestRotateWithConfig_DisabledRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := RotateWithConfig(cfg, true, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestRotateWithConfig_RemoteStorageRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	cfg.Storage.Type = "remote"
	err := RotateWithConfig(cfg, true, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal for remote storage")
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Fatalf("expected a remote-storage error, got: %v", err)
	}
}

func TestRotateWithConfig_WithoutConfirmRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	err := RotateWithConfig(cfg, false, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal without --confirm")
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected a --confirm guidance error, got: %v", err)
	}
}

// rotateFixture bootstraps a real keydir + migrated DB in the current
// (chdir'd) directory and returns the cfg plus a single already-encrypted
// PasswordReset row's plaintext token, for rotation-correctness assertions.
func rotateFixture(t *testing.T) (cfg *config.Config, plaintextToken string, userID uint) {
	t.Helper()
	cfg = testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap InitWithConfig: %v", err)
	}

	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)

	baseDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, baseDir, db)
	if err := authEnc.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("authEnc.Initialize: %v", err)
	}
	defer authEnc.Shutdown()

	userID = 42
	plaintextToken = "s3cr3t-reset-token-value"
	enc, meta, err := authEnc.EncryptPasswordResetToken(plaintextToken, userID)
	if err != nil {
		t.Fatalf("EncryptPasswordResetToken: %v", err)
	}
	row := models.PasswordReset{UserID: userID, Token: "", EncryptedToken: enc, TokenMetadata: models.JSON(meta)}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create password_reset row: %v", err)
	}
	return cfg, plaintextToken, userID
}

// decryptPasswordResetRow re-opens the DB and decrypts the (assumed single)
// password_reset row under the CURRENT on-disk DEK/KEK, for asserting
// rotation preserved the plaintext.
func decryptPasswordResetRow(t *testing.T, cfg *config.Config, passphrase string, userID uint) string {
	t.Helper()
	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)
	baseDir, _ := os.Getwd()
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, baseDir, db)
	if err := authEnc.Initialize(passphrase); err != nil {
		t.Fatalf("authEnc.Initialize: %v", err)
	}
	defer authEnc.Shutdown()

	var row models.PasswordReset
	if err := db.Where("user_id = ?", userID).First(&row).Error; err != nil {
		t.Fatalf("read password_reset row: %v", err)
	}
	plain, err := authEnc.DecryptPasswordResetToken(row.EncryptedToken, []byte(row.TokenMetadata), userID)
	if err != nil {
		t.Fatalf("DecryptPasswordResetToken: %v", err)
	}
	return plain
}

func TestRotateWithConfig_Success_PreservesPlaintextAndChangesDEK(t *testing.T) {
	chdirTemp(t)
	cfg, plaintext, userID := rotateFixture(t)

	oldDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key before rotation: %v", err)
	}

	if _, err := captureOutput(t, func() error {
		return RotateWithConfig(cfg, true, false, zeroPassSrc())
	}); err != nil {
		t.Fatalf("RotateWithConfig: %v", err)
	}

	newDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key after rotation: %v", err)
	}
	if bytes.Equal(oldDEKBytes, newDEKBytes) {
		t.Fatal("dek.key must change after a real rotation")
	}

	got := decryptPasswordResetRow(t, cfg, testBaselinePassphrase, userID)
	if got != plaintext {
		t.Fatalf("secret did not round-trip through rotation: got %q, want %q", got, plaintext)
	}
}

func TestRotateWithConfig_WrongPassphrase_FailsClosedLeavesDEKUntouched(t *testing.T) {
	chdirTemp(t)
	cfg, plaintext, userID := rotateFixture(t)

	oldDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key before rotation: %v", err)
	}

	setPassphraseEnv(t, testWrongPassphrase)
	stdout, err := captureOutput(t, func() error {
		return RotateWithConfig(cfg, true, false, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected rotation to fail with the wrong passphrase")
	}
	if strings.Contains(stdout+err.Error(), testWrongPassphrase) {
		t.Fatal("passphrase leaked into stdout/error output")
	}

	newDEKBytes, rerr := os.ReadFile("dek.key")
	if rerr != nil {
		t.Fatalf("read dek.key after failed rotation: %v", rerr)
	}
	if !bytes.Equal(oldDEKBytes, newDEKBytes) {
		t.Fatal("dek.key must be untouched after a failed rotation")
	}
	if _, err := os.Stat("dek.key.pending"); err == nil {
		t.Fatal("no dek.key.pending should survive a failed rotation attempt")
	}

	// Existing data must still be readable under the original passphrase.
	setPassphraseEnv(t, testBaselinePassphrase)
	got := decryptPasswordResetRow(t, cfg, testBaselinePassphrase, userID)
	if got != plaintext {
		t.Fatalf("data corrupted by failed rotation attempt: got %q, want %q", got, plaintext)
	}
}

func TestDryRunRotation_NoChangesToDiskOrDB(t *testing.T) {
	chdirTemp(t)
	cfg, plaintext, userID := rotateFixture(t)

	oldDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key before dry run: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	var before models.PasswordReset
	if err := db.Where("user_id = ?", userID).First(&before).Error; err != nil {
		t.Fatalf("read row before dry run: %v", err)
	}
	closeTestDB(db)

	if _, err := captureOutput(t, func() error {
		return RotateWithConfig(cfg, false, true, zeroPassSrc())
	}); err != nil {
		t.Fatalf("dry-run RotateWithConfig: %v", err)
	}

	newDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key after dry run: %v", err)
	}
	if !bytes.Equal(oldDEKBytes, newDEKBytes) {
		t.Fatal("dry run must not change dek.key")
	}

	db2 := migrateEncOpsTables(t, testDBFile)
	var after models.PasswordReset
	if err := db2.Where("user_id = ?", userID).First(&after).Error; err != nil {
		t.Fatalf("read row after dry run: %v", err)
	}
	closeTestDB(db2)
	if !bytes.Equal(before.EncryptedToken, after.EncryptedToken) {
		t.Fatal("dry run must not modify any row's ciphertext")
	}

	got := decryptPasswordResetRow(t, cfg, testBaselinePassphrase, userID)
	if got != plaintext {
		t.Fatalf("dry run corrupted data: got %q, want %q", got, plaintext)
	}
}

func TestRotateWithConfig_RefusesWhileServerHoldsExclusiveLock(t *testing.T) {
	chdirTemp(t)
	cfg, _, _ := rotateFixture(t)

	baseDir, _ := os.Getwd()
	holder := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := holder.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("holder.Initialize: %v", err)
	}
	if err := holder.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("holder.AcquireExclusiveKeyLock: %v", err)
	}
	defer holder.Shutdown()

	_, err := captureOutput(t, func() error {
		return RotateWithConfig(cfg, true, false, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected rotation to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "stop the running server") {
		t.Fatalf("expected the explicit lock-contention message, got: %v", err)
	}
}

// --- ValidateWithConfig / StatusWithConfig / FixPermsWithConfig ---------

func TestValidateWithConfig_Disabled_NoError(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	if err := ValidateWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("expected nil error when disabled, got %v", err)
	}
}

func TestValidateWithConfig_WrongPassphraseFails(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	setPassphraseEnv(t, testWrongPassphrase)
	if err := ValidateWithConfig(cfg, zeroPassSrc()); err == nil {
		t.Fatal("expected validate to fail with the wrong passphrase")
	}
}

func TestValidateWithConfig_GoodPassphraseSucceeds(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := ValidateWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("ValidateWithConfig: %v", err)
	}
}

func TestStatusWithConfig_DisabledReturnsNilNeverErrors(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	if err := StatusWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("StatusWithConfig must always return nil, got %v", err)
	}
}

func TestStatusWithConfig_WrongPassphraseStillReturnsNil(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	setPassphraseEnv(t, testWrongPassphrase)
	stdout, err := captureOutput(t, func() error {
		return StatusWithConfig(cfg, zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("StatusWithConfig must always return nil (status is read-only reporting), got %v", err)
	}
	if strings.Contains(stdout, testWrongPassphrase) || strings.Contains(stdout, testBaselinePassphrase) {
		t.Fatal("passphrase leaked into status output")
	}
}

func TestFixPermsWithConfig_Disabled_Refuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := FixPermsWithConfig(cfg, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestFixPermsWithConfig_TightensLoosePermissions(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := os.Chmod("dek.key", 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.Chmod("kek.salt", 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := FixPermsWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("FixPermsWithConfig: %v", err)
	}
	if mode := fileMode(t, "dek.key"); mode != 0o600 {
		t.Fatalf("expected dek.key mode 0600 after fix-perms, got %v", mode)
	}
	if mode := fileMode(t, "kek.salt"); mode != 0o600 {
		t.Fatalf("expected kek.salt mode 0600 after fix-perms, got %v", mode)
	}
}

// --- UpgradeAADWithConfig: validation gates ------------------------------

func TestUpgradeAADWithConfig_DisabledRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := UpgradeAADWithConfig(cfg, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestUpgradeAADWithConfig_RemoteStorageRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	cfg.Storage.Type = "remote"
	err := UpgradeAADWithConfig(cfg, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal for remote storage")
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Fatalf("expected a remote-storage error, got: %v", err)
	}
}
