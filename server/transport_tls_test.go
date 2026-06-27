package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// A group/world-readable key file must fail closed when the permission check is enabled,
// warn (no error) by default, and be allowed when explicitly overridden. A 0600 file or a
// missing file (first boot) passes.
func TestEnforceKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.key")
	salt := filepath.Join(dir, "kek.salt")
	mk := func(p string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // defeat umask
			t.Fatal(err)
		}
	}

	base := func() *config.Config {
		c := &config.Config{}
		c.Storage.Encryption.Enabled = true
		c.Storage.Encryption.DEKPath = dek
		c.Storage.Encryption.SaltPath = salt
		return c
	}

	// 0600 files → ok regardless of the flag.
	mk(dek, 0600)
	mk(salt, 0600)
	if err := enforceKeyFilePermissions(base()); err != nil {
		t.Errorf("0600 key files must pass: %v", err)
	}

	// World-readable DEK + strict check → fail closed.
	mk(dek, 0644)
	strict := base()
	strict.Security.EnableFilePermissionCheck = true
	if err := enforceKeyFilePermissions(strict); err == nil {
		t.Error("world-readable key with enable_file_permission_check must fail closed")
	}

	// Same file, default (no strict flag) → warn only, no error.
	if err := enforceKeyFilePermissions(base()); err != nil {
		t.Errorf("default mode must warn, not fail: %v", err)
	}

	// Strict but explicitly overridden → allowed.
	override := base()
	override.Security.EnableFilePermissionCheck = true
	override.Security.AllowUnsafeFilePermissions = true
	if err := enforceKeyFilePermissions(override); err != nil {
		t.Errorf("allow_unsafe_file_permissions must override: %v", err)
	}
}

func cfgWith(httpEnabled, httpTLS, grpcEnabled, grpcTLS, require bool) *config.Config {
	c := &config.Config{}
	c.Server.HTTP.Enabled = httpEnabled
	c.Server.HTTP.TLS.Enabled = httpTLS
	c.Server.GRPC.Enabled = grpcEnabled
	c.Server.GRPC.TLS.Enabled = grpcTLS
	c.Security.RequireTransportTLS = require
	return c
}

func TestCheckTransportTLSPosture(t *testing.T) {
	// require_transport_tls + a cleartext enabled listener → fail closed.
	if err := checkTransportTLSPosture(cfgWith(true, false, false, false, true)); err == nil {
		t.Error("expected failure: HTTP cleartext with require_transport_tls set")
	}
	if err := checkTransportTLSPosture(cfgWith(false, false, true, false, true)); err == nil {
		t.Error("expected failure: gRPC cleartext with require_transport_tls set")
	}
	// require set but both listeners have TLS → ok.
	if err := checkTransportTLSPosture(cfgWith(true, true, true, true, true)); err != nil {
		t.Errorf("TLS on both listeners must pass even with require set: %v", err)
	}
	// require OFF + cleartext → no error (warns only).
	if err := checkTransportTLSPosture(cfgWith(true, false, true, false, false)); err != nil {
		t.Errorf("cleartext without require must not fail: %v", err)
	}
	// a disabled listener is ignored even under require.
	if err := checkTransportTLSPosture(cfgWith(false, false, false, false, true)); err != nil {
		t.Errorf("no enabled listeners must pass: %v", err)
	}
}
