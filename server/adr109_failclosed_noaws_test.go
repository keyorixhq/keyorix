//go:build noaws

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// This file is the ADR-109 step 6 S2 proof, for the noaws tag, that a
// server binary compiled without AWS support REFUSES TO START (never fails
// open, never silently skips) when the operator's config explicitly enables
// an AWS-backed feature this binary does not have — naming the offending
// feature and why. Each test drives the real boot path
// (initializeCoreService/initializeEncryption), not just the underlying
// registry, so it also proves the wiring in server/main.go that turns a
// registry ok=false into a boot failure actually fires.

// TestWireBackendRotation_AWSIAM_NoAWSBuild_FailsBoot proves a configured
// aws-iam rotation backend refuses to boot in a noaws build.
func TestWireBackendRotation_AWSIAM_NoAWSBuild_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "prod-aws-iam", Type: "aws-iam", Region: "us-east-1", AllowedRefs: []string{"svc-"}},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an aws-iam rotation backend in a noaws build")
	}
	if !strings.Contains(err.Error(), "prod-aws-iam") || !strings.Contains(err.Error(), "aws-iam") {
		t.Fatalf("expected error to name the offending backend and its type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "noaws") {
		t.Fatalf("expected error to name the excluding build tag, got: %v", err)
	}
}

// TestWireConnect_AWSSecretsManager_NoAWSBuild_FailsBoot proves a configured
// aws-secrets-manager connector refuses to boot in a noaws build — the exact
// "a stored connect config for AWS SM on an air-gapped build" scenario named
// in the track spec.
func TestWireConnect_AWSSecretsManager_NoAWSBuild_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "prod-aws-sm", Type: "aws-secrets-manager", Scope: "platform", Region: "us-east-1"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an aws-secrets-manager connector in a noaws build")
	}
	if !strings.Contains(err.Error(), "prod-aws-sm") || !strings.Contains(err.Error(), "aws-secrets-manager") {
		t.Fatalf("expected error to name the offending connector and its type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "noaws") {
		t.Fatalf("expected error to name the excluding build tag, got: %v", err)
	}
}

// TestInitializeEncryption_AWSKMS_NoAWSBuild_FailsBoot proves a configured
// aws-kms key provider refuses to boot in a noaws build, and — the "no
// secret material or success leaks" half of S2 — that no *encryption.Service
// is returned alongside the error (there is nothing a caller could
// accidentally use to encrypt/decrypt with a provider that was never built).
func TestInitializeEncryption_AWSKMS_NoAWSBuild_FailsBoot(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "unused-not-reached")
	t.Chdir(t.TempDir()) // DEKPath/SaltPath/the DEK lock file must be relative (initializeEncryption's own doc comment)
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test.db"},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
				KeyProvider: config.KeyProviderConfig{
					Type:     "aws-kms",
					KMSKeyID: "arn:aws:kms:us-east-1:123456789012:key/unused",
				},
			},
		},
	}
	svc, err := initializeEncryption(cfg, nil)
	if err == nil {
		t.Fatal("expected initializeEncryption to fail with an aws-kms key provider in a noaws build")
	}
	if svc != nil {
		t.Fatalf("expected a nil *encryption.Service alongside the error, got %#v", svc)
	}
	if !strings.Contains(err.Error(), "aws-kms") {
		t.Fatalf("expected error to name the offending key provider type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("expected error to say the provider is unavailable in this build, got: %v", err)
	}
}
