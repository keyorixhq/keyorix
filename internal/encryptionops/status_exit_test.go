package encryptionops

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption"
)

// `encryption status` must exit non-zero (StatusWithConfig returns an error)
// when it cannot read the key state, while still printing the same diagnostic
// line as before (docs/operator/key-rotation-runbook.md quotes the text). A
// preflight `encryption status && encryption rotate --confirm` otherwise
// continues past a failed state check (#4270). Healthy and Enabled:false keep
// returning nil (TestStatusWithConfig_Disabled..., TestStatusWithConfig_Healthy...).

func TestStatusWithConfig_WrongPassphraseReturnsErrorAndPrintsDiagnostic(t *testing.T) {
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
	if err == nil {
		t.Fatal("status must return an error (non-zero exit) when the DEK cannot be unwrapped")
	}
	if !strings.Contains(stdout, "❌") || !strings.Contains(stdout, "failed to unwrap DEK") {
		t.Fatalf("the ❌ diagnostic line must still be printed, got:\n%s", stdout)
	}
	if strings.Contains(stdout, testWrongPassphrase) || strings.Contains(stdout, testBaselinePassphrase) {
		t.Fatal("passphrase leaked into status output")
	}
}

func TestStatusWithConfig_LiveServerHoldsDEKLockReturnsErrorAndPrintsDiagnostic(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	baseDir, _ := os.Getwd()
	holder := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := holder.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("holder.Initialize: %v", err)
	}
	if err := holder.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("holder.AcquireExclusiveKeyLock: %v", err)
	}
	defer holder.Shutdown()

	stdout, err := captureOutput(t, func() error {
		return StatusWithConfig(cfg, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("status must return an error (non-zero exit) while another process holds the DEK lock")
	}
	if !strings.Contains(stdout, "❌") || !strings.Contains(stdout, "holds the DEK lock exclusively") {
		t.Fatalf("the ❌ diagnostic line must still be printed, got:\n%s", stdout)
	}
}

func TestStatusWithConfig_NoPassphraseSourceReturnsErrorAndPrintsDiagnostic(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	setPassphraseEnv(t, "")

	stdout, err := captureOutput(t, func() error {
		return StatusWithConfig(cfg, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("status must return an error (non-zero exit) when no passphrase source is configured")
	}
	if !strings.Contains(stdout, "⚠️") {
		t.Fatalf("the ⚠️ diagnostic line must still be printed, got:\n%s", stdout)
	}
}

func TestStatusWithConfig_HealthyReturnsNil(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	stdout, err := captureOutput(t, func() error {
		return StatusWithConfig(cfg, zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("a healthy key set must exit 0, got %v", err)
	}
	if !strings.Contains(stdout, "Initialized: ✅") {
		t.Fatalf("expected the healthy status line, got:\n%s", stdout)
	}
}
