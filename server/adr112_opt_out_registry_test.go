// adr112_opt_out_registry_test.go -- ADR-112 (secure-by-default baseline,
// item 2): the opt-out rule's server-side wiring. The registry itself and
// its structural guarantees live in internal/config
// (insecure_settings_registry.go / insecure_settings_registry_test.go);
// these tests cover the three loops server/main.go runs over it.
package main

import (
	"regexp"
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

// internalMarker matches text that is meant for the maintainers' working
// notes, not for an operator reading the boot log (#2979: "NEEDS ANDREI",
// "item 1", "polarity-inverted rename", "not a boolean today", issue numbers).
var internalMarker = regexp.MustCompile(`(?i)needs andrei|andrei|polarity|\bitem [0-9]|not a boolean today|known exception|#[0-9]{3,}`)

// Every start-up warning the registry loop can print must read as operator
// text. The zero-value config has several entries in effect (empty
// metrics_token, rate limiting off, TLS off, ...), so its boot log is the
// worst case for the "WARNING: ... is in effect" lines the demo showed.
func TestWarnInsecureSettingsInEffect_NoInternalMarkersInBootLog(t *testing.T) {
	out := captureLogs(func() { warnInsecureSettingsInEffect(&config.Config{}) })
	if !strings.Contains(out, "is in effect") {
		t.Fatalf("test premise broken: the zero-value config should have warnings in effect, got %q", out)
	}
	if m := internalMarker.FindString(out); m != "" {
		t.Errorf("boot log leaks an internal marker %q:\n%s", m, out)
	}
}

// The same check for every registry entry's description, in effect or not,
// so a setting nobody has in effect today cannot reintroduce a marker.
func TestInsecureSettingsRegistry_DescribeIsOperatorText(t *testing.T) {
	for _, s := range config.InsecureSettingsRegistry {
		if m := internalMarker.FindString(s.Describe); m != "" {
			t.Errorf("%s: Describe leaks an internal marker %q: %q", s.Name, m, s.Describe)
		}
	}
}
