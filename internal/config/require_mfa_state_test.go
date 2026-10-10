package config

import "testing"

// TestRequireMFAState_FollowsTheBootPath pins each combination of the fields
// Load() and applyADR112UpgradeGrace set (#2986), including the hand-built
// shapes: the grace flag alone selects the grace state (the posture report
// sets only the flag; the boot also clears RequireMFA), and a Go zero value is
// "off", never a silent pass.
func TestRequireMFAState_FollowsTheBootPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		sec  SecurityConfig
		want RequireMFAState
		weak bool
	}{
		{"explicit false", SecurityConfig{}, RequireMFAOff, true},
		{"explicit true", SecurityConfig{RequireMFA: true}, RequireMFAEnforcingExplicit, false},
		{"implicit, enforced", SecurityConfig{RequireMFA: true, RequireMFAImplicitDefault: true}, RequireMFAEnforcingImplicit, false},
		{"grace as the boot leaves it", SecurityConfig{RequireMFAImplicitDefault: true, RequireMFAUpgradeGrace: true}, RequireMFAGraceNotEnforced, true},
		{"grace flag alone, as the posture report leaves it", SecurityConfig{RequireMFA: true, RequireMFAImplicitDefault: true, RequireMFAUpgradeGrace: true}, RequireMFAGraceNotEnforced, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sec.RequireMFAState(); got != tc.want {
				t.Errorf("state = %q, want %q", got, tc.want)
			}
			if got := tc.sec.RequireMFAState().Weakened(); got != tc.weak {
				t.Errorf("Weakened = %v, want %v", got, tc.weak)
			}
		})
	}
	if !RequireMFAState("some-future-state").Weakened() {
		t.Error("an unknown state must count as weakened (fail closed)")
	}
}
