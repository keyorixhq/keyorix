package encryption

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestRotateWithConfig_RequiresConfirm verifies the --confirm gate.
// Without confirm=true, the function must reject the request before doing
// any DB or encryption work. This is the safety gate documented in the
// ADR-010 addendum.
func TestRotateWithConfig_RequiresConfirm(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
	}

	err := rotateWithConfig(cfg, false)
	if err == nil {
		t.Fatal("expected error when --confirm is not passed, got nil")
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Errorf("expected error message to mention --confirm, got: %v", err)
	}
}

// TestRotateWithConfig_RejectsRemoteStorage verifies that the command refuses
// to run against a remote-mode CLI. Rotation must run on the server host
// against the actual database. The check fires before any DB/encryption work.
func TestRotateWithConfig_RejectsRemoteStorage(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "remote",
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
	}

	err := rotateWithConfig(cfg, true)
	if err == nil {
		t.Fatal("expected error for remote storage type, got nil")
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Errorf("expected error message to mention remote storage, got: %v", err)
	}
}

// TestRotateWithConfig_RejectsDisabledEncryption verifies that the command
// refuses to run when encryption is disabled in configuration. There is
// nothing to rotate.
func TestRotateWithConfig_RejectsDisabledEncryption(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: false,
			},
		},
	}

	err := rotateWithConfig(cfg, true)
	if err == nil {
		t.Fatal("expected error when encryption is disabled, got nil")
	}
	if !strings.Contains(err.Error(), "encryption is disabled") {
		t.Errorf("expected error to mention disabled encryption, got: %v", err)
	}
}
