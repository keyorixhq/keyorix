package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSecretValueEncryptedAtRest is the regression test for the plaintext-at-rest
// vulnerability: the real production bootstrap (initializeCoreService, called by
// server/main.go's main()) with storage.encryption.enabled derived a KEK/DEK but
// never wired it into the secret-value write path, so every secret was persisted as
// cleartext regardless of encryption config.
//
// It drives the EXACT real bootstrap with encryption enabled, creates a secret
// through the real core.CreateSecret API (what every HTTP/gRPC handler calls), then:
//   - reads the raw secret_versions row directly and asserts the stored bytes are NOT
//     the plaintext (i.e. genuinely encrypted at rest), with encryption metadata set;
//   - reads the value back through the real API and asserts it round-trips to the
//     original plaintext.
func TestSecretValueEncryptedAtRest(t *testing.T) {
	i18n.ResetForTesting()
	t.Cleanup(i18n.ResetForTesting)
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n init: %v", err)
	}

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "correct horse battery staple")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "verify.db"},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
			},
		},
	}

	coreService, encSvc, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService failed: %v", err)
	}
	if encSvc == nil {
		t.Fatal("initializeEncryption returned nil even though encryption.enabled=true")
	}
	if !coreService.SecretValueEncryptionActive() {
		t.Fatal("secret-value encryption is not active after bootstrap with encryption enabled")
	}

	ctx := context.Background()
	project, err := coreService.CreateProject(ctx, "verify-encryption-project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	db, err := gorm.Open(sqlite.Open("verify.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("reopening db: %v", err)
	}
	env := &models.Environment{ProjectID: project.ID, Name: "verify-env"}
	if err := db.Create(env).Error; err != nil {
		t.Fatalf("creating environment: %v", err)
	}

	const plaintext = "THIS-IS-THE-SECRET-PLAINTEXT-VALUE-0xDEADBEEF"
	secret, err := coreService.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "verify-secret",
		Value:         []byte(plaintext),
		ProjectID:     project.ID,
		EnvironmentID: env.ID,
		Type:          "password",
		CreatedBy:     "verify-test",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	// 1) At rest: the raw stored bytes must be ciphertext, not the plaintext, and the
	//    row must carry encryption metadata (algorithm set).
	var version models.SecretVersion
	if err := db.Where("secret_node_id = ?", secret.ID).First(&version).Error; err != nil {
		t.Fatalf("reading back secret version: %v", err)
	}
	if bytes.Equal(version.EncryptedValue, []byte(plaintext)) {
		t.Fatalf("REGRESSION: secret value stored as PLAINTEXT at rest: %q", string(version.EncryptedValue))
	}
	if !strings.Contains(string(version.EncryptionMetadata), "AES-256-GCM") {
		t.Errorf("expected AES-256-GCM encryption metadata, got %q", string(version.EncryptionMetadata))
	}

	// 2) Round-trip: reading through the real API must return the original plaintext.
	got, err := coreService.GetSecretValue(ctx, secret.ID)
	if err != nil {
		t.Fatalf("GetSecretValue: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("round-trip mismatch: got %q, want %q", string(got), plaintext)
	}
}
