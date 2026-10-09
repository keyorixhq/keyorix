package encryptionops

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- AuthStatusWithConfig --------------------------------------------------

func TestAuthStatusWithConfig_EnabledReportsStats(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)

	stdout, err := captureOutput(t, func() error {
		return AuthStatusWithConfig(cfg, zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("AuthStatusWithConfig: %v", err)
	}
	if !strings.Contains(stdout, "ENABLED") {
		t.Fatalf("expected status output to report ENABLED, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "API Clients") {
		t.Fatalf("expected status output to include stats, got:\n%s", stdout)
	}
}

func TestAuthStatusWithConfig_WrongPassphraseFailsClosed(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)

	setPassphraseEnv(t, testWrongPassphrase)
	stdout, err := captureOutput(t, func() error {
		return AuthStatusWithConfig(cfg, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected AuthStatusWithConfig to fail with the wrong passphrase")
	}
	if strings.Contains(stdout+err.Error(), testWrongPassphrase) {
		t.Fatal("passphrase leaked into stdout/error output")
	}
}

// --- EnableAuthEncryptionWithConfig -----------------------------------------

func TestEnableAuthEncryptionWithConfig_DisabledWithoutForceRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled and --force is not set")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestEnableAuthEncryptionWithConfig_WrongPassphraseFailsClosed(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)

	setPassphraseEnv(t, testWrongPassphrase)
	stdout, err := captureOutput(t, func() error {
		return EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected EnableAuthEncryptionWithConfig to fail with the wrong passphrase")
	}
	if strings.Contains(stdout+err.Error(), testWrongPassphrase) {
		t.Fatal("passphrase leaked into stdout/error output")
	}
}

// TestEnableAuthEncryptionWithConfig_AlreadyEnabledShortCircuit_NeverFires
// documents a real (non-security) bug: EnableAuthEncryptionWithConfig reads
// authEnc.GetAuthEncryptionStatus() to decide whether to print "already
// enabled" and skip re-initializing, but it reads that status BEFORE ever
// calling authEnc.Initialize() -- Service.IsInitialized() is only ever true
// AFTER Initialize sets the internal flag, so status["initialized"] is
// unconditionally false at that call site and the short-circuit can never
// fire. This test documents the current (buggy) behavior: even calling
// enable twice in a row with --force=false never prints "already enabled" or
// skips its own re-init work. Filed as a plain bug, not fixed here per this
// session's test-only scope (see internal/encryptionops/auth_encryption.go:124).
func TestEnableAuthEncryptionWithConfig_AlreadyEnabledShortCircuit_NeverFires(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	closeTestDB(db)

	for i := 0; i < 2; i++ {
		db := migrateEncOpsTables(t, testDBFile)
		stdout, err := captureOutput(t, func() error {
			return EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
		})
		closeTestDB(db)
		if err != nil {
			t.Fatalf("call %d: EnableAuthEncryptionWithConfig: %v", i, err)
		}
		if strings.Contains(stdout, "already enabled") {
			t.Fatalf("call %d: got the 'already enabled' short-circuit message — the dead-code bug this test documents appears to be fixed; update/remove this test", i)
		}
	}
}

// --- RotateAuthEncryptionWithConfig -----------------------------------------

func TestRotateAuthEncryptionWithConfig_WithoutConfirmRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	err := RotateAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal without --confirm")
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected a --confirm guidance error, got: %v", err)
	}
}

func TestRotateAuthEncryptionWithConfig_Success_PreservesPlaintextAndChangesDEK(t *testing.T) {
	chdirTemp(t)
	cfg, plaintext, userID := rotateFixture(t)

	oldDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key before rotation: %v", err)
	}

	if _, err := captureOutput(t, func() error {
		return RotateAuthEncryptionWithConfig(cfg, true, zeroPassSrc())
	}); err != nil {
		t.Fatalf("RotateAuthEncryptionWithConfig: %v", err)
	}

	newDEKBytes, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key after rotation: %v", err)
	}
	if string(oldDEKBytes) == string(newDEKBytes) {
		t.Fatal("dek.key must change after auth-encryption rotate")
	}

	got := decryptPasswordResetRow(t, cfg, testBaselinePassphrase, userID)
	if got != plaintext {
		t.Fatalf("secret did not round-trip through auth-encryption rotate: got %q, want %q", got, plaintext)
	}
}

// --- MigrateAuthDataWithConfig / MigratePasswordResetTokens -----------------

func TestMigrateAuthDataWithConfig_DryRun_WritesNothing(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	row := models.PasswordReset{UserID: 7, Token: "plaintext-reset-token"}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create row: %v", err)
	}
	closeTestDB(db)

	if _, err := captureOutput(t, func() error {
		return MigrateAuthDataWithConfig(cfg, true, zeroPassSrc())
	}); err != nil {
		t.Fatalf("dry-run migrate: %v", err)
	}

	db2 := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db2)
	var after models.PasswordReset
	if err := db2.First(&after, row.ID).Error; err != nil {
		t.Fatalf("read row after dry run: %v", err)
	}
	if after.Token != "plaintext-reset-token" {
		t.Fatalf("dry run modified the plaintext token: got %q", after.Token)
	}
	if len(after.EncryptedToken) != 0 {
		t.Fatal("dry run must not populate encrypted_token")
	}
}

func TestMigrateAuthDataWithConfig_EncryptsEveryPlaintextRow_IdempotentOnRerun(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	row := models.PasswordReset{UserID: 9, Token: "plaintext-reset-token-2"}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create row: %v", err)
	}
	closeTestDB(db)

	if _, err := captureOutput(t, func() error {
		return MigrateAuthDataWithConfig(cfg, false, zeroPassSrc())
	}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	db2 := migrateEncOpsTables(t, testDBFile)
	var after models.PasswordReset
	if err := db2.First(&after, row.ID).Error; err != nil {
		t.Fatalf("read row after migrate: %v", err)
	}
	if after.Token != "" {
		t.Fatalf("expected the plaintext token column to be cleared, got %q", after.Token)
	}
	if len(after.EncryptedToken) == 0 {
		t.Fatal("expected encrypted_token to be populated")
	}
	firstEncrypted := append([]byte(nil), after.EncryptedToken...)
	closeTestDB(db2)

	got := decryptPasswordResetRow(t, cfg, testBaselinePassphrase, 9)
	if got != "plaintext-reset-token-2" {
		t.Fatalf("migrated token did not decrypt to the original plaintext: got %q", got)
	}

	// Idempotent: a second migrate pass finds no remaining plaintext rows and
	// does not touch the already-migrated row.
	if _, err := captureOutput(t, func() error {
		return MigrateAuthDataWithConfig(cfg, false, zeroPassSrc())
	}); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	db3 := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db3)
	var after2 models.PasswordReset
	if err := db3.First(&after2, row.ID).Error; err != nil {
		t.Fatalf("read row after second migrate: %v", err)
	}
	if string(after2.EncryptedToken) != string(firstEncrypted) {
		t.Fatal("a second migrate pass re-touched an already-migrated row")
	}
}

// --- ValidateAuthEncryptionWithConfig / ValidatePasswordResetTokens --------

func TestValidateAuthEncryptionWithConfig_AllMigrated_Passes(t *testing.T) {
	chdirTemp(t)
	cfg, _, _ := rotateFixture(t)

	if err := ValidateAuthEncryptionWithConfig(cfg, false, zeroPassSrc()); err != nil {
		t.Fatalf("ValidateAuthEncryptionWithConfig: %v", err)
	}
}

func TestValidateAuthEncryptionWithConfig_DetectsUnmigratedRow(t *testing.T) {
	chdirTemp(t)
	cfg, _, _ := rotateFixture(t)

	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)
	if err := db.Create(&models.PasswordReset{UserID: 99, Token: "never-migrated"}).Error; err != nil {
		t.Fatalf("create unmigrated row: %v", err)
	}

	err := ValidateAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected validate to detect the unmigrated plaintext row")
	}
}

func TestValidateAuthEncryptionWithConfig_DetectsCorruptedRow(t *testing.T) {
	chdirTemp(t)
	cfg, _, userID := rotateFixture(t)

	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)
	var row models.PasswordReset
	if err := db.Where("user_id = ?", userID).First(&row).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	corrupted := append([]byte{}, row.EncryptedToken...)
	corrupted[len(corrupted)-1] ^= 0xFF
	if err := db.Model(&row).Update("encrypted_token", corrupted).Error; err != nil {
		t.Fatalf("corrupt row: %v", err)
	}

	err := ValidateAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	if err == nil {
		t.Fatal("expected validate to fail on a corrupted (tamper-detected) row")
	}
}
