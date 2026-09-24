package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestRunTrustKeygen_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 8's own test requirement) against
// internal/cli/trust/trust.go's keygenCmd -- the one command in this ported surface
// with no server call at all.
func TestRunTrustKeygen_MatchesOldCLIOutputShape(t *testing.T) {
	dir := t.TempDir()
	trustKeygenPurpose = "update"
	trustKeygenKeyID = "update-2026"
	trustKeygenDir = dir
	trustKeygenForce = false

	out := captureStdout(t, func() {
		if err := trustKeygenCmd.RunE(trustKeygenCmd, nil); err != nil {
			t.Fatalf("trust keygen: %v", err)
		}
	})
	if !containsAll(out, `Generated update signing keypair "update-2026":`, "KEEP OFFLINE", "-X github.com/keyorixhq/keyorix/internal/trust.updateKeysB64=update-2026=") {
		t.Fatalf("output missing expected fields: %q", out)
	}

	privPath := filepath.Join(dir, "update-2026.private.pem")
	pubPath := filepath.Join(dir, "update-2026.public.pem")
	for _, p := range []string{privPath, pubPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", p, info.Mode().Perm())
		}
	}
	privPEM, err := os.ReadFile(privPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	blk, _ := pem.Decode(privPEM)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatalf("private key PEM block = %+v", blk)
	}
	if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
		t.Fatalf("parse private key: %v", err)
	}
}

func TestRunTrustKeygen_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	trustKeygenPurpose = "license"
	trustKeygenKeyID = "license-2026"
	trustKeygenDir = dir
	trustKeygenForce = false

	captureStdout(t, func() {
		if err := trustKeygenCmd.RunE(trustKeygenCmd, nil); err != nil {
			t.Fatalf("first keygen: %v", err)
		}
	})
	err := trustKeygenCmd.RunE(trustKeygenCmd, nil)
	if err == nil {
		t.Fatalf("expected the second keygen without --force to be refused")
	}
	if !containsAll(err.Error(), "already exists") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunTrustKeygen_RequiresPurposeAndKeyID(t *testing.T) {
	dir := t.TempDir()
	trustKeygenDir = dir
	trustKeygenForce = false

	trustKeygenPurpose = ""
	trustKeygenKeyID = "x"
	if err := trustKeygenCmd.RunE(trustKeygenCmd, nil); err == nil {
		t.Fatalf("expected an error for a missing --purpose")
	}

	trustKeygenPurpose = "update"
	trustKeygenKeyID = ""
	if err := trustKeygenCmd.RunE(trustKeygenCmd, nil); err == nil {
		t.Fatalf("expected an error for a missing --key-id")
	}
}
