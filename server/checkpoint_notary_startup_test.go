// checkpoint_notary_startup_test.go — startup TLS-scheme validation for
// audit.checkpoint_notary (Wave 6 #baseline/notary-findings.json#1): a plaintext
// http:// TSA URL (non-loopback) must fail closed at startup — initializeCoreService
// must refuse to build a server that would silently anchor checkpoints over an
// unencrypted, tamperable channel. Plain http to a loopback host (local dev/test)
// remains accepted, mirroring this codebase's convention elsewhere
// (internal/storage/remote's validateBaseURL, server/main.go's requireSecureOrLoopback).
//
// The companion behavior — enabling the notary WITHOUT a trust root
// (ca_cert_path) must NOT fail startup, but must leave CheckpointAnchorVerifiable()
// false — is covered by TestInitializeCoreService_CheckpointNotary_WithURL_NoCA and
// TestInitializeCoreService_CheckpointNotary_ValidCA in server_s4_test.go.
package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_CheckpointNotary_RejectsPlaintextHTTPURL confirms a
// plaintext http:// TSA URL to a non-loopback host fails startup outright.
func TestInitializeCoreService_CheckpointNotary_RejectsPlaintextHTTPURL(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Audit.CheckpointNotary = config.CheckpointNotaryConfig{
		Enabled: true,
		URL:     "http://tsa.example.com/tsr",
	}

	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to fail closed on a plaintext http TSA URL, got nil error")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("expected error to explain the https requirement, got: %v", err)
	}
}

// TestInitializeCoreService_CheckpointNotary_AcceptsLoopbackHTTPURL confirms the
// documented local-testing exception still works at startup: plain http to a
// loopback host is accepted.
func TestInitializeCoreService_CheckpointNotary_AcceptsLoopbackHTTPURL(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Audit.CheckpointNotary = config.CheckpointNotaryConfig{
		Enabled: true,
		URL:     "http://127.0.0.1:9999/tsr",
	}

	_, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService with a loopback http TSA URL: %v", err)
	}
}
