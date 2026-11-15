package encryptionops

import (
	"os"
	"strings"
	"testing"
)

// `encryption init` with encryption disabled in the configuration cannot do its
// job (it creates no keys), so it must exit non-zero while still printing the
// same ❌ line (FixPermsWithConfig already refuses the same way). Before, it
// printed ❌ and returned nil, so a bootstrap script's `encryption init && ...`
// carried on with no keys (#4270 sweep).
func TestInitWithConfig_Disabled_ReturnsErrorAndPrintsDiagnostic(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)

	stdout, err := captureOutput(t, func() error {
		return InitWithConfig(cfg, zeroPassSrc())
	})
	if err == nil {
		t.Fatal("init must return an error (non-zero exit) when encryption is disabled in the configuration")
	}
	if !strings.Contains(stdout, "❌ Encryption is disabled in configuration") {
		t.Fatalf("the ❌ diagnostic line must still be printed, got:\n%s", stdout)
	}
	if _, statErr := os.Stat("dek.key"); statErr == nil {
		t.Fatal("dek.key must not be created when encryption is disabled")
	}
}
