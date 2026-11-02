package config

import (
	"crypto/fips140"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeWebhookSigningConfig writes a minimal config with the webhook channel
// enabled and the given signing secret.
func writeWebhookSigningConfig(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n" +
		"notifications:\n  webhook:\n    enabled: true\n    endpoint: https://siem.example.com/hook\n" +
		"    signing_secret: " + secret + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// loadThenValidate is the boot sequence of server/main.go: Load, then Validate.
func loadThenValidate(t *testing.T, path string) error {
	t.Helper()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg.Validate()
}

// FIPS-TAILS-2 item 2, red/green: under GODEBUG=fips140=only a webhook signing
// secret under 14 bytes made every delivery panic in crypto/hmac. Config
// validation now refuses it at boot, naming the minimum.
func TestWebhookSigningSecret_UnderFIPS140Only_ShortRejectedAtValidate(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; TestValidateNotificationsSection_* cover default mode")
	}
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	err := loadThenValidate(t, writeWebhookSigningConfig(t, "short-secret"))
	if err == nil {
		t.Fatal("a 12-byte signing secret was accepted under fips140=only; every signed delivery would panic")
	}
	if !strings.Contains(err.Error(), "at least 14 bytes") {
		t.Fatalf("the refusal must name the minimum: %v", err)
	}
	if err := loadThenValidate(t, writeWebhookSigningConfig(t, "fourteen-bytes")); err != nil {
		t.Fatalf("a 14-byte signing secret must be accepted: %v", err)
	}
}
