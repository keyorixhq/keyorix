// adr112_opt_out_registry_test.go -- ADR-112 (secure-by-default baseline,
// item 2): the opt-out rule's server-side wiring. The registry itself and
// its structural guarantees live in internal/config
// (insecure_settings_registry.go / insecure_settings_registry_test.go);
// these tests cover the three loops server/main.go runs over it.
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
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

// Every DeprecatedSettingWarnings entry config.Load produced gets its own
// logged line — this is the ONLY place those warnings are surfaced, since
// config.Load itself is side-effect-free (see its own doc comment).
func TestWarnDeprecatedSettingAliases_LogsEachWarning(t *testing.T) {
	cfg := &config.Config{DeprecatedSettingWarnings: []string{"alpha is deprecated", "beta is deprecated"}}
	logged := captureLogs(func() { warnDeprecatedSettingAliases(cfg) })
	for _, want := range cfg.DeprecatedSettingWarnings {
		if !strings.Contains(logged, want) {
			t.Errorf("expected logged output to contain %q, got: %q", want, logged)
		}
	}

	none := &config.Config{}
	logged = captureLogs(func() { warnDeprecatedSettingAliases(none) })
	if logged != "" {
		t.Errorf("no deprecated warnings must log nothing, got: %q", logged)
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

// TestResolveADR112BootPosture_GracePeriodWarnsAndIsDiffed is #2908 at the
// boot path: an upgraded deployment (users, no enforcement marker) that never
// set security.enable_file_permission_check only WARNS on a failed startup
// check, so the opt-out warning must name insecure_skip_startup_validation and
// the settings-diff snapshot must record grace-warn-only. Once the marker
// ratchets it to enforced, neither appears and the snapshot value changes --
// which is what makes leaving the grace period an audited transition.
// RED if resolveADR112BootPosture warns before applying the grace decision.
func TestResolveADR112BootPosture_GracePeriodWarnsAndIsDiffed(t *testing.T) {
	const name = "security.insecure_skip_startup_validation"
	for _, tc := range []struct {
		label     string
		marker    bool
		wantWarn  bool
		wantValue config.StartupValidationState
	}{
		{"upgrade in grace period", false, true, config.StartupValidationGraceWarnOnly},
		{"upgrade past grace period", true, false, config.StartupValidationEnforcingImplicit},
	} {
		t.Run(tc.label, func(t *testing.T) {
			adr112GraceSoftened.Store(false)
			cfg := adr112GraceConfig(t)
			migrateADR112DB(t, cfg, 2)
			if tc.marker {
				db, err := appstorage.OpenGormDB(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := recordADR112Enforced(db, adr112FilePermEnforcedKey, time.Now()); err != nil {
					t.Fatal(err)
				}
				closeGormDB(db)
			}
			logs := captureLogs(func() { resolveADR112BootPosture(cfg) })
			if got := strings.Contains(logs, "WARNING: "+name+" is in effect"); got != tc.wantWarn {
				t.Errorf("opt-out warning for %s: got %v, want %v; logs:\n%s", name, got, tc.wantWarn, logs)
			}
			if got := securityPostureSnapshot(cfg)[name]; got != string(tc.wantValue) {
				t.Errorf("settings-diff value = %q, want %q", got, tc.wantValue)
			}
		})
	}
}
