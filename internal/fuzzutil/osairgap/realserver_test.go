package osairgap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalLocalConfig is a storage-less (local SQLite) air-gap config: no cloud
// connectors, no external storage, encryption off, file-permission checks off so
// it boots unattended. Per docs/security/egress-inventory.md, this shape "has no
// outbound destination at all" — so a correct Keyorix makes ZERO egress booting
// it, which is exactly what the jail asserts at the OS level.
const minimalLocalConfig = `
locale:
  language: en
  fallback_language: en
storage:
  type: local
  database:
    path: "%DBPATH%"
  encryption:
    enabled: false
security:
  enable_file_permission_check: false
  auto_fix_file_permissions: false
  allow_unsafe_file_permissions: true
server:
  http:
    enabled: true
    port: "18080"
soft_delete:
  enabled: true
  retention_days: 30
`

// TestAirgap_RealServerBoot boots the REAL keyorix-server binary inside the net
// namespace with a local-SQLite config and asserts zero egress across startup
// (config load, crypto/FIPS self-test, storage open, i18n, HTTP listen on
// loopback — the task's "startup / update-check / telemetry / DNS / NTP / license"
// surface, all of which Keyorix is designed to never trigger). Gated behind
// AGP1_SERVER_BIN (path to a prebuilt binary) so routine CI is not burdened with
// a full server build; run in this campaign for the AGP1 report. The binary's
// own package init() runs too, so a transitively-imported library that dialed at
// init — something the source-level egressguard scanner cannot see — would be
// caught here.
func TestAirgap_RealServerBoot(t *testing.T) {
	bin := os.Getenv("AGP1_SERVER_BIN")
	if bin == "" {
		t.Skip("set AGP1_SERVER_BIN to a prebuilt keyorix-server to run the real-boot air-gap check")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("AGP1_SERVER_BIN %q not usable: %v", bin, err)
	}
	requireNetns(t)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	cfg := strings.ReplaceAll(minimalLocalConfig, "%DBPATH%", dbPath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := Run(ctx, os.Args[0], RunSpec{
		Argv: []string{bin},
		Env: []string{
			"KEYORIX_CONFIG_PATH=" + cfgPath,
			"KEYORIX_MASTER_PASSWORD=agp1-airgap-boot-passphrase",
			"HOME=" + dir,
		},
		// The server listens and blocks; let it run ~8s under the sampler, then
		// the jail's timeout kills it. 8s at 5ms sampling ≈ 1600 /proc reads.
		Timeout:        8 * time.Second,
		SampleInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jail Run: %v", err)
	}
	t.Logf("real-server boot: lo_up=%v exit=%d canaryHits=%v procPeers=%v samples=%d",
		res.LoUp, res.TargetExit, res.CanaryHits, res.ProcPeers, res.ProcSamples)
	t.Logf("server stderr tail:\n%s", res.TargetStderrTail)

	// The air-gap oracle: NO egress intent (canary) and NO non-loopback direct
	// dial (proc), across the whole boot. DB is nil (local storage), so loopback
	// is the only allowed destination.
	if v := (Allowlist{}).violations(res); len(v) != 0 {
		t.Fatalf("AIR-GAP VIOLATION: real keyorix-server boot attempted egress: %v", v)
	}
	if res.ProcSamples < 2 {
		t.Errorf("sampler ran only %d times — the boot may have exited before any sample; egress evidence is weak", res.ProcSamples)
	}
}

// TestAirgap_RealCLI jails the real keyorix CLI running a local, server-less
// subcommand and asserts zero egress. Gated behind AGP1_CLI_BIN. The CLI only
// talks to a server URL the user gives it (egress-allowlist class E16); a help/
// version invocation gives none, so the OS-level expectation is zero egress.
func TestAirgap_RealCLI(t *testing.T) {
	bin := os.Getenv("AGP1_CLI_BIN")
	if bin == "" {
		t.Skip("set AGP1_CLI_BIN to a prebuilt keyorix CLI to run the real-CLI air-gap check")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("AGP1_CLI_BIN %q not usable: %v", bin, err)
	}
	requireNetns(t)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, os.Args[0], RunSpec{
		Argv:           []string{bin, "--help"},
		Env:            []string{"HOME=" + dir},
		Timeout:        10 * time.Second,
		SampleInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jail Run: %v", err)
	}
	t.Logf("real-CLI: lo_up=%v exit=%d canaryHits=%v procPeers=%v samples=%d stderrTail=%q",
		res.LoUp, res.TargetExit, res.CanaryHits, res.ProcPeers, res.ProcSamples, res.TargetStderrTail)
	if v := (Allowlist{}).violations(res); len(v) != 0 {
		t.Fatalf("AIR-GAP VIOLATION: keyorix CLI --help attempted egress: %v", v)
	}
}
