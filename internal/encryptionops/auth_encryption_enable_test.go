package encryptionops

import (
	"os"
	"strings"
	"testing"
)

// #2915: EnableAuthEncryptionWithConfig's "already enabled" short-circuit used to
// read IsInitialized() on a brand-new AuthEncryption, which is always false before
// Initialize runs, so the message could never print. "Already enabled" now means
// what an operator means by it: the wrapped DEK was already on disk when the
// command started.
func TestEnableAuthEncryptionWithConfig_AlreadyEnabledReportedOnSecondRun(t *testing.T) {
	chdirTemp(t)
	setPassphraseEnv(t, testBaselinePassphrase)
	cfg := testConfig(true)
	db := migrateEncOpsTables(t, testDBFile)
	closeTestDB(db)

	out, err := captureOutput(t, func() error {
		return EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("first enable: %v", err)
	}
	if !strings.Contains(out, "enabled successfully") || strings.Contains(out, "already enabled") {
		t.Fatalf("first run must report fresh enablement, got:\n%s", out)
	}
	if _, err := os.Stat("dek.key"); err != nil {
		t.Fatalf("first run must provision the DEK: %v", err)
	}

	out, err = captureOutput(t, func() error {
		return EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("second enable: %v", err)
	}
	if !strings.Contains(out, "already enabled") {
		t.Errorf("second run must report \"already enabled\", got:\n%s", out)
	}
	if strings.Contains(out, "enabled successfully") {
		t.Errorf("second run must not claim a fresh enablement, got:\n%s", out)
	}

	// --force re-runs the full path and reports it as a fresh enablement.
	out, err = captureOutput(t, func() error {
		return EnableAuthEncryptionWithConfig(cfg, true, zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("forced enable: %v", err)
	}
	if !strings.Contains(out, "enabled successfully") {
		t.Errorf("--force run must report enablement, got:\n%s", out)
	}
}

// The already-enabled report must not skip passphrase verification: a wrong
// passphrase against existing keys still fails closed.
func TestEnableAuthEncryptionWithConfig_AlreadyEnabledStillVerifiesPassphrase(t *testing.T) {
	chdirTemp(t)
	setPassphraseEnv(t, testBaselinePassphrase)
	cfg := testConfig(true)
	db := migrateEncOpsTables(t, testDBFile)
	closeTestDB(db)

	if _, err := captureOutput(t, func() error {
		return EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	}); err != nil {
		t.Fatalf("first enable: %v", err)
	}

	setPassphraseEnv(t, testWrongPassphrase)
	out, err := captureOutput(t, func() error {
		return EnableAuthEncryptionWithConfig(cfg, false, zeroPassSrc())
	})
	if err == nil {
		t.Fatalf("wrong passphrase against existing keys must fail, got success:\n%s", out)
	}
	if strings.Contains(out, "already enabled") {
		t.Errorf("must not report already-enabled when the passphrase is wrong:\n%s", out)
	}
}
