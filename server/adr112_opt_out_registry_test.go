// adr112_opt_out_registry_test.go -- ADR-112 (secure-by-default baseline,
// item 2): the opt-out rule's server-side wiring. The registry itself and
// its structural guarantees live in internal/config
// (insecure_settings_registry.go / insecure_settings_registry_test.go);
// these tests cover the three loops server/main.go runs over it.
package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Flipping ONE setting's InEffect from false to true adds exactly one new
// warning line naming it, without disturbing whatever else a baseline
// config legitimately warns about (a bare zero-value *config.Config is NOT
// itself "clean" -- e.g. an empty metrics_token, or rate limiting defaulting
// disabled, are both genuinely in-effect weak states on the Go zero value by
// construction; this test isolates the one setting under test rather than
// asserting a raw zero-value config logs nothing at all).
func TestWarnInsecureSettingsInEffect_WarnsOnlyWhenInEffect(t *testing.T) {
	baseline := &config.Config{}
	before := captureLogs(func() { warnInsecureSettingsInEffect(baseline) })
	if strings.Contains(before, "security.insecure_allow_unsafe_file_permissions") {
		t.Fatal("test premise broken: the baseline must not already warn about this specific setting")
	}

	weak := &config.Config{}
	weak.Security.AllowUnsafeFilePermissions = true
	after := captureLogs(func() { warnInsecureSettingsInEffect(weak) })
	if !strings.Contains(after, "security.insecure_allow_unsafe_file_permissions") {
		t.Errorf("expected a warning naming the in-effect setting, got: %q", after)
	}
}

// securityPostureSnapshot must cover every registry entry exactly once --
// the settings-diff audit depends on this to see the whole picture every
// boot, not just whichever entries happen to be in effect right now (an
// entry flipping from in-effect back to not-in-effect is itself a change
// that must be diffable, which requires it being in BOTH snapshots).
func TestSecurityPostureSnapshot_CoversEveryRegistryEntryExactlyOnce(t *testing.T) {
	cfg := &config.Config{}
	snapshot := securityPostureSnapshot(cfg)
	if len(snapshot) != len(config.InsecureSettingsRegistry) {
		t.Fatalf("snapshot has %d entries, registry has %d", len(snapshot), len(config.InsecureSettingsRegistry))
	}
	for _, s := range config.InsecureSettingsRegistry {
		val, ok := snapshot[s.Name]
		if !ok {
			t.Errorf("snapshot missing entry %q", s.Name)
			continue
		}
		if want := s.Value(cfg); val != want {
			t.Errorf("snapshot[%q] = %q, want %q", s.Name, val, want)
		}
	}
}
