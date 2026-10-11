package config

import "testing"

// skipStartupValidationEntry returns the registry entry for
// security.enable_file_permission_check (#2908).
func skipStartupValidationEntry(t *testing.T) InsecureSetting {
	t.Helper()
	for _, e := range InsecureSettingsRegistry {
		if e.Name == "security.insecure_skip_startup_validation" {
			return e
		}
	}
	t.Fatal("security.insecure_skip_startup_validation is not registered")
	return InsecureSetting{}
}

// startupValidationFixtures are the four shapes security.enable_file_permission_check
// can be in at boot, built the way Load() and applyADR112UpgradeGrace leave them.
func startupValidationFixtures() map[string]SecurityConfig {
	return map[string]SecurityConfig{
		// enable_file_permission_check: false written in the config file.
		"off": {EnableFilePermissionCheck: false},
		// Key absent, upgraded deployment with no enforcement marker: the
		// server WARNS instead of refusing to start (#2908's gap).
		"grace": {EnableFilePermissionCheck: true, EnableFilePermissionCheckImplicitDefault: true, EnableFilePermissionCheckUpgradeGrace: true},
		// Key absent, fresh install or already ratcheted past the grace period.
		"implicit": {EnableFilePermissionCheck: true, EnableFilePermissionCheckImplicitDefault: true},
		// enable_file_permission_check: true written in the config file.
		"explicit": {EnableFilePermissionCheck: true},
	}
}

// TestInsecureSkipStartupValidation_GracePeriodIsADeviation is #2908's red
// test: during the ADR-112 upgrade grace period the server only warns about a
// failed startup check, so the registry must report the weak state as in
// effect -- the start-up warning, the settings diff and the posture report all
// read this entry.
func TestInsecureSkipStartupValidation_GracePeriodIsADeviation(t *testing.T) {
	e := skipStartupValidationEntry(t)
	wantInEffect := map[string]bool{"off": true, "grace": true, "implicit": false, "explicit": false}
	for name, sec := range startupValidationFixtures() {
		cfg := &Config{Security: sec}
		if got := e.InEffect(cfg); got != wantInEffect[name] {
			t.Errorf("%s: InEffect = %v, want %v", name, got, wantInEffect[name])
		}
	}
}

// TestInsecureSkipStartupValidation_SettingsDiffSeesEveryState: the
// start-to-start settings diff compares Value strings, so every state must
// have its own value -- otherwise entering or leaving the grace period, or
// writing the key down, is never audited.
func TestInsecureSkipStartupValidation_SettingsDiffSeesEveryState(t *testing.T) {
	e := skipStartupValidationEntry(t)
	seen := map[string]string{}
	for name, sec := range startupValidationFixtures() {
		v := e.Value(&Config{Security: sec})
		if prev, dup := seen[v]; dup {
			t.Errorf("states %q and %q share the settings-diff value %q: a transition between them is never audited", prev, name, v)
		}
		seen[v] = name
	}
}

// TestStartupValidationState_FollowsTheBootPath pins each fixture's state, and
// the one hand-built shape the boot path can still reach: UpgradeGrace without
// ImplicitDefault. runStartupValidation softens on UpgradeGrace alone, so that
// shape must read as grace, never as enforcing.
func TestStartupValidationState_FollowsTheBootPath(t *testing.T) {
	want := map[string]StartupValidationState{
		"off":      StartupValidationOff,
		"grace":    StartupValidationGraceWarnOnly,
		"implicit": StartupValidationEnforcingImplicit,
		"explicit": StartupValidationEnforcingExplicit,
	}
	for name, sec := range startupValidationFixtures() {
		if got := sec.StartupValidationState(); got != want[name] {
			t.Errorf("%s: state = %q, want %q", name, got, want[name])
		}
	}
	handBuilt := SecurityConfig{EnableFilePermissionCheck: true, EnableFilePermissionCheckUpgradeGrace: true}
	if got := handBuilt.StartupValidationState(); got != StartupValidationGraceWarnOnly {
		t.Errorf("UpgradeGrace without ImplicitDefault: state = %q, want %q", got, StartupValidationGraceWarnOnly)
	}
	if !StartupValidationState("some-future-state").Weakened() {
		t.Error("Weakened must fail closed: an unknown state counts as a deviation")
	}
}
