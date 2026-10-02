// adr112_startup_validation_keys_test.go — the blocker the coordinator's second
// review named (2026-10-06): runStartupValidation called
// startup.ValidateStartupTolerant UNCONDITIONALLY, so the tolerance reached
// deployments that had set security.enable_file_permission_check explicitly.
//
// Why that is a fail-open and not a cosmetic inconsistency: the tolerance's one
// job is to treat "KEK salt AND wrapped DEK both missing" as a fresh install.
// With it in force, a key volume that failed to mount is indistinguishable from
// first boot, so startup validation PASSES, and initializeEncryption then
// generates a brand-new salt and DEK — over an existing, still-encrypted
// database whose real key material is merely unmounted. Every secret value in
// it becomes permanently unreadable, and the process logs a clean start while
// doing it.
//
// The existing TestRunStartupValidation_ExplicitTrue_StillFailsClosed does NOT
// cover this, which is exactly why the regression read as guarded: its fixture
// writes a real 32-byte salt and a real 60-byte DEK and makes the DEK
// world-readable, so it passes on a PERMISSIONS failure. Permissions are
// checked before the encryption block and are not subject to the tolerance at
// all. The explicit-opt-in + missing-key-material path had no test.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeADR112MissingKeysConfig builds the deployment shape that actually reaches
// the fail-open: encryption enabled, dek_path/salt_path pointing at files that
// do not exist (an unmounted key volume), a database file that already exists,
// and security.allow_unsafe_file_permissions: true.
//
// That last key is not a convenience to get past an inconvenient check — it is
// what makes the bug reachable, and it is the common case rather than an exotic
// one. validateFilePermissions runs BEFORE validateEncryption and cannot help
// complaining about an absent key file (securefiles.FixFilePerms counts a failed
// open as "unresolved"), so without allow_unsafe_file_permissions the boot
// refuses for a PERMISSIONS reason and the encryption tolerance is never
// reached. With it, the operator has said "permission mismatches on my key files
// are warnings" — which is exactly what a Kubernetes deployment mounting key
// material as a secret has to say, since the mounted files are owned by a
// different uid than the process. Those are precisely the deployments whose key
// volume can fail to mount. The flag speaks about PERMISSIONS; it must not also
// switch off "the key material has to exist".
//
// So the fixture isolates the encryption check as the thing under test, and
// TestRunStartupValidation_ExplicitTrue_MissingKeys_WithoutUnsafePerms_RefusesOnPermissions
// below pins the other arm so the two reasons for refusing stay distinguishable.
//
// The config goes through config.Load so the real explicit/implicit tracking
// machinery decides EnableFilePermissionCheckImplicitDefault, rather than the
// test asserting against a hand-set struct field that could drift from what
// Load actually produces.
func writeADR112MissingKeysConfig(t *testing.T, explicitCheck bool) *config.Config {
	t.Helper()
	dir := t.TempDir()
	// Deliberately NOT created: this is the unmounted-key-volume shape.
	dek := filepath.Join(dir, "dek.key")
	salt := filepath.Join(dir, "kek.salt")
	dbPath := filepath.Join(dir, "keyorix.db")

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// A database that already exists is the whole danger: it is the encrypted
	// data a freshly generated DEK would orphan.
	must(os.WriteFile(dbPath, []byte("sqlite"), 0o600))

	securityBlock := "security:\n  allow_unsafe_file_permissions: true\n"
	if explicitCheck {
		securityBlock += "  enable_file_permission_check: true\n"
	}
	configPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n" +
		"  type: local\n" +
		"  database:\n" +
		"    path: " + dbPath + "\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: " + dek + "\n" +
		"    salt_path: " + salt + "\n" +
		securityBlock
	must(os.WriteFile(configPath, []byte(content), 0o600))

	t.Setenv("KEYORIX_CONFIG_PATH", configPath)
	cfg, err := config.Load(configPath)
	must(err)

	// Guard the fixture's own premise: if either file somehow exists, the test
	// below would be asserting about a different scenario entirely.
	for _, p := range []string{dek, salt} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("fixture premise broken: %s must not exist (stat err = %v)", p, err)
		}
	}
	return cfg
}

// TestRunStartupValidation_ExplicitTrue_MissingKeyMaterial_RefusesToStart is
// the red/green for the blocker. RED on the pre-fix line
// (`startup.ValidateStartupTolerant(configPath, false)` with no
// explicit/implicit gate): runStartupValidation returns nil, boot continues,
// and initializeEncryption goes on to write fresh key material over the
// existing database.
func TestRunStartupValidation_ExplicitTrue_MissingKeyMaterial_RefusesToStart(t *testing.T) {
	cfg := writeADR112MissingKeysConfig(t, true)
	if cfg.Security.EnableFilePermissionCheckImplicitDefault {
		t.Fatal("test premise broken: an explicitly-set key must NOT resolve as an implicit default")
	}
	if !cfg.Storage.Encryption.Enabled {
		t.Fatal("test premise broken: encryption must be enabled for validateEncryption to run")
	}

	var err error
	logged := captureLogs(func() { err = runStartupValidation(cfg) })

	if err == nil {
		t.Fatal("an explicit enable_file_permission_check=true with NO key material must refuse to start: " +
			"continuing lets initializeEncryption generate a fresh salt/DEK over an existing encrypted database")
	}
	// Attribution, not just failure: the refusal must come from the encryption
	// check. A permission or database failure passing this assertion would mean
	// the test proves something other than what its name claims.
	if !strings.Contains(err.Error(), "encryption validation failed") {
		t.Errorf("expected the refusal to come from the ENCRYPTION check (the one the tolerance softens), got: %v", err)
	}
	if !strings.Contains(logged, "KEK salt file not found") && !strings.Contains(logged, "wrapped DEK file not found") {
		t.Errorf("expected the logged startup-validation error to name the missing key file, got: %q", logged)
	}
	// The exact sentence the tolerance would have produced instead. Asserting
	// its ABSENCE is what makes this test fail on the pre-fix code rather than
	// merely on some unrelated error.
	if strings.Contains(logged, "treating as first boot") {
		t.Errorf("an explicit opt-in must never reach the first-boot tolerance, got: %q", logged)
	}
	if strings.Contains(logged, "Startup validation passed") {
		t.Errorf("startup validation must not report success here, got: %q", logged)
	}
}

// TestRunStartupValidation_ImplicitDefault_MissingKeyMaterial_StillBoots is the
// companion that stops the fix from being made in the wrong direction. The
// tolerance exists for a real reason — on a genuine fresh install the keys are
// generated a few hundred milliseconds later by the same boot sequence — so
// removing it outright, rather than gating it, would turn every first boot of
// an upgraded deployment that never set the key into an outage.
//
// This is the case that must still pass, and it is why the fix is a gate and
// not a deletion.
func TestRunStartupValidation_ImplicitDefault_MissingKeyMaterial_StillBoots(t *testing.T) {
	cfg := writeADR112MissingKeysConfig(t, false)
	if !cfg.Security.EnableFilePermissionCheckImplicitDefault {
		t.Fatal("test premise broken: an absent key must resolve as an implicit default")
	}

	var err error
	logged := captureLogs(func() { err = runStartupValidation(cfg) })

	if err != nil {
		t.Fatalf("a deployment that never set the key must still complete a first boot with no key material yet: %v", err)
	}
	if !strings.Contains(logged, "treating as first boot") {
		t.Errorf("expected the first-boot tolerance to be the reason this booted, got: %q", logged)
	}
}

// TestRunStartupValidation_ExplicitFalse_SkipsTheCheckEntirely pins the third
// arm of the explicit/implicit split, so the fix cannot be read as having
// changed the opt-OUT path: an explicit false still skips startup validation
// altogether and says so, exactly as before. enforceKeyFilePermissions remains
// the always-on backstop for that deployment (it is called separately, right
// after this, and is not gated on the flag).
func TestRunStartupValidation_ExplicitFalse_SkipsTheCheckEntirely(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	if err := os.WriteFile(dbPath, []byte("sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n" +
		"  type: local\n" +
		"  database:\n" +
		"    path: " + dbPath + "\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: " + filepath.Join(dir, "dek.key") + "\n" +
		"    salt_path: " + filepath.Join(dir, "kek.salt") + "\n" +
		"security:\n  enable_file_permission_check: false\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYORIX_CONFIG_PATH", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.EnableFilePermissionCheck {
		t.Fatal("test premise broken: an explicit false must resolve to false")
	}

	var verr error
	logged := captureLogs(func() { verr = runStartupValidation(cfg) })
	if verr != nil {
		t.Errorf("an explicit opt-out must skip the check, not fail: %v", verr)
	}
	if !strings.Contains(logged, "are SKIPPED") {
		t.Errorf("expected the opt-out to say the checks were skipped, got: %q", logged)
	}
}

// TestRunStartupValidation_ExplicitTrue_MissingKeys_WithoutUnsafePerms_RefusesOnPermissions
// pins the OTHER arm, so the two reasons for refusing stay distinguishable and
// the fixture's use of allow_unsafe_file_permissions above is not mistaken for
// a convenience. Without that flag, the same missing-key-material deployment
// already refuses — but on a PERMISSIONS verdict from validateFilePermissions,
// which runs first and counts a failed open as unresolved, never reaching the
// encryption tolerance at all.
//
// This is what made the fail-open look narrower than it is, and why it needs
// its own test rather than a comment: the refusal here comes from a check that
// says nothing about whether the key material exists, so an operator who turns
// permission complaints into warnings (the Kubernetes mounted-secret case)
// loses the "keys must exist" refusal along with it.
func TestRunStartupValidation_ExplicitTrue_MissingKeys_WithoutUnsafePerms_RefusesOnPermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	if err := os.WriteFile(dbPath, []byte("sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n" +
		"  type: local\n" +
		"  database:\n" +
		"    path: " + dbPath + "\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: " + filepath.Join(dir, "dek.key") + "\n" +
		"    salt_path: " + filepath.Join(dir, "kek.salt") + "\n" +
		"security:\n  enable_file_permission_check: true\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYORIX_CONFIG_PATH", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.AllowUnsafeFilePermissions {
		t.Fatal("test premise broken: allow_unsafe_file_permissions must be off for this arm")
	}

	verr := runStartupValidation(cfg)
	if verr == nil {
		t.Fatal("expected a refusal even without allow_unsafe_file_permissions")
	}
	if !strings.Contains(verr.Error(), "file permission validation failed") {
		t.Errorf("expected this arm to refuse on PERMISSIONS (the check that runs before encryption), got: %v", verr)
	}
}
