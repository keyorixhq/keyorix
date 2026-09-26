package cmd

import (
	"strings"
	"testing"
)

// CLI-LOGIN-001 regression guard: login.go previously called neither
// warnIfInsecureEndpoint nor warnInsecureFlag, unlike every sibling command that
// persists or transmits credentials (systeminit.go, user.go). These tests exercise the
// extracted resolveLoginServerURL/resolveLoginPassword helpers directly -- no live
// server needed.

func TestResolveLoginServerURL_WarnsOnInsecureEndpoint(t *testing.T) {
	loginServerURL = "http://example.com"
	defer func() { loginServerURL = "" }()

	out := captureStderr(t, func() {
		if _, err := resolveLoginServerURL(); err != nil {
			t.Fatalf("resolveLoginServerURL: %v", err)
		}
	})
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "insecure") && !strings.Contains(lower, "cleartext") && !strings.Contains(out, "HTTPS") {
		t.Fatalf("expected an insecure-endpoint warning, got: %q", out)
	}
}

func TestResolveLoginServerURL_NoWarningOnHTTPS(t *testing.T) {
	loginServerURL = "https://example.com"
	defer func() { loginServerURL = "" }()

	out := captureStderr(t, func() {
		if _, err := resolveLoginServerURL(); err != nil {
			t.Fatalf("resolveLoginServerURL: %v", err)
		}
	})
	if out != "" {
		t.Fatalf("expected no warning for an https endpoint, got: %q", out)
	}
}

func TestResolveLoginServerURL_NoWarningOnLoopback(t *testing.T) {
	loginServerURL = "http://127.0.0.1:8080"
	defer func() { loginServerURL = "" }()

	out := captureStderr(t, func() {
		if _, err := resolveLoginServerURL(); err != nil {
			t.Fatalf("resolveLoginServerURL: %v", err)
		}
	})
	if out != "" {
		t.Fatalf("expected no warning for a loopback endpoint, got: %q", out)
	}
}

func TestResolveLoginPassword_WarnsWhenPassedAsFlag(t *testing.T) {
	// warnInsecureFlag checks cmd.Flags().Changed, not just the bound variable's
	// value -- Set (not a direct assignment) is what marks the flag Changed.
	if err := loginCmd.Flags().Set("password", "hunter2"); err != nil {
		t.Fatalf("set --password flag: %v", err)
	}
	defer func() {
		loginPassword = ""
		loginCmd.Flags().Lookup("password").Changed = false
	}()

	out := captureStderr(t, func() {
		p, err := resolveLoginPassword(loginCmd)
		if err != nil {
			t.Fatalf("resolveLoginPassword: %v", err)
		}
		if p != "hunter2" {
			t.Fatalf("expected the flag value back, got %q", p)
		}
	})
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "insecure") || strings.Contains(out, "hunter2") {
		t.Fatalf("expected an insecure-flag warning naming --password but never the value, got: %q", out)
	}
}
