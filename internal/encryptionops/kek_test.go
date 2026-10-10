package encryptionops

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

func TestRotateKEKWithConfig_DisabledRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestRotateKEKWithConfig_RemoteStorageRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	cfg.Storage.Type = "remote"
	err := RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal for remote storage")
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Fatalf("expected a remote-storage error, got: %v", err)
	}
}

func TestRotateKEKWithConfig_WithoutConfirmRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	err := RotateKEKWithConfig(cfg, false, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal without --confirm")
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected a --confirm guidance error, got: %v", err)
	}
}

// kekFixture bootstraps a real keydir in the current (chdir'd) dir and
// encrypts one probe secret under the baseline passphrase's KEK, returning
// the ciphertext/metadata for post-rotation round-trip assertions.
func kekFixture(t *testing.T) (cfg *config.Config, probeCT, probeMeta []byte) {
	t.Helper()
	cfg = testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap InitWithConfig: %v", err)
	}

	baseDir, _ := os.Getwd()
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := svc.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("svc.Initialize: %v", err)
	}
	defer svc.Shutdown()
	var err error
	probeCT, probeMeta, err = svc.EncryptSecret([]byte("kek-rotation-probe-value"))
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	_ = probeMeta
	return cfg, probeCT, probeMeta
}

func TestRotateKEKWithConfig_OldEqualsNewRefuses(t *testing.T) {
	chdirTemp(t)
	cfg, _, _ := kekFixture(t)
	setNewPassphraseEnv(t, testBaselinePassphrase) // same as old
	if _, err := captureOutput(t, func() error {
		return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	}); err == nil {
		t.Fatal("expected refusal when the new passphrase equals the old one")
	}
}

func TestRotateKEKWithConfig_WrongOldPassphraseFailsClosed(t *testing.T) {
	chdirTemp(t)
	cfg, probeCT, _ := kekFixture(t)

	oldSalt, err := os.ReadFile("kek.salt")
	if err != nil {
		t.Fatalf("read kek.salt: %v", err)
	}
	oldDEK, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}

	setPassphraseEnv(t, testWrongPassphrase)
	setNewPassphraseEnv(t, testNewPassphrase)
	stdout, err := captureOutput(t, func() error {
		return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected KEK rotation to fail with the wrong old passphrase")
	}
	if strings.Contains(stdout+err.Error(), testWrongPassphrase) || strings.Contains(stdout+err.Error(), testNewPassphrase) {
		t.Fatal("a passphrase leaked into stdout or the returned error")
	}

	newSalt, _ := os.ReadFile("kek.salt")
	newDEK, _ := os.ReadFile("dek.key")
	if !bytes.Equal(oldSalt, newSalt) {
		t.Fatal("kek.salt must be untouched after a failed KEK rotation")
	}
	if !bytes.Equal(oldDEK, newDEK) {
		t.Fatal("dek.key must be untouched after a failed KEK rotation")
	}

	// The original passphrase must still open everything and decrypt the probe.
	baseDir, _ := os.Getwd()
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := svc.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("original passphrase no longer works after failed rotation: %v", err)
	}
	defer svc.Shutdown()
	got, err := svc.DecryptSecret(probeCT)
	if err != nil || string(got) != "kek-rotation-probe-value" {
		t.Fatalf("probe did not survive failed rotation: got %q, err %v", got, err)
	}
}

func TestRotateKEKWithConfig_Success_NewPassphraseWorksOldDoesNot(t *testing.T) {
	chdirTemp(t)
	cfg, probeCT, _ := kekFixture(t)

	setPassphraseEnv(t, testBaselinePassphrase)
	setNewPassphraseEnv(t, testNewPassphrase)
	if _, err := captureOutput(t, func() error {
		return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	}); err != nil {
		t.Fatalf("RotateKEKWithConfig: %v", err)
	}

	baseDir, _ := os.Getwd()

	// New passphrase opens it and the DEK's plaintext value is unchanged
	// (the probe, encrypted under the OLD KEK-wrapped DEK, still decrypts).
	newSvc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := newSvc.Initialize(testNewPassphrase); err != nil {
		t.Fatalf("new passphrase must open the rotated KEK: %v", err)
	}
	got, err := newSvc.DecryptSecret(probeCT)
	newSvc.Shutdown()
	if err != nil || string(got) != "kek-rotation-probe-value" {
		t.Fatalf("DEK value changed across KEK rotation: got %q, err %v", got, err)
	}

	// Old passphrase must no longer unwrap the DEK.
	oldSvc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	err = oldSvc.Initialize(testBaselinePassphrase)
	oldSvc.Shutdown()
	if err == nil {
		t.Fatal("old passphrase must be rejected after a KEK rotation")
	}
}

func TestRotateKEKWithConfig_RefusesWhileServerHoldsExclusiveLock(t *testing.T) {
	chdirTemp(t)
	cfg, _, _ := kekFixture(t)

	baseDir, _ := os.Getwd()
	holder := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := holder.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("holder.Initialize: %v", err)
	}
	if err := holder.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("holder.AcquireExclusiveKeyLock: %v", err)
	}
	defer holder.Shutdown()

	setPassphraseEnv(t, testBaselinePassphrase)
	setNewPassphraseEnv(t, testNewPassphrase)
	_, err := captureOutput(t, func() error {
		return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected KEK rotation to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "stop the running server") {
		t.Fatalf("expected the explicit lock-contention message, got: %v", err)
	}
}
