package config

// RequireMFAState is what security.require_mfa actually does on this boot
// (#2986). A boolean cannot say it: an explicit `require_mfa: false` is an
// opt-out, and during ADR-112's upgrade grace period server/main.go's
// applyADR112UpgradeGrace sets RequireMFA back to false for the boot while
// RequireMFAUpgradeGrace records why. Both weaken the baseline; neither had a
// registry entry, so neither got a start-up warning or a settings-diff line.
//
// The values are the settings-diff Value of the
// security.insecure_disable_mfa_requirement registry entry, so each must stay
// distinct: a transition between any two is a security-relevant change the
// start-to-start diff has to audit. Same shape as StartupValidationState.
type RequireMFAState string

const (
	// RequireMFAOff: require_mfa: false is written in the config file. In
	// effect (a deviation).
	RequireMFAOff RequireMFAState = "off"
	// RequireMFAGraceNotEnforced: the key is absent and this boot is an upgraded
	// deployment inside ADR-112's grace period (RequireMFAUpgradeGrace): MFA is
	// NOT enforced yet. In effect (a deviation).
	RequireMFAGraceNotEnforced RequireMFAState = "grace-not-enforced"
	// RequireMFAEnforcingImplicit: the key is absent and the deployment is
	// enforced (a fresh install, or one already ratcheted past the grace period
	// by the adr112.require_mfa.enforced marker). Not in effect: this is
	// ADR-112's default.
	RequireMFAEnforcingImplicit RequireMFAState = "enforcing-implicit"
	// RequireMFAEnforcingExplicit: require_mfa: true is written in the config
	// file. Not in effect.
	RequireMFAEnforcingExplicit RequireMFAState = "enforcing-explicit"
)

// RequireMFAState derives the state from the fields Load() and server/main.go's
// applyADR112UpgradeGrace set. RequireMFAUpgradeGrace selects the grace state
// first: the boot path sets RequireMFA false under it, but the posture report
// sets only the flag, and both must read as grace.
func (s *SecurityConfig) RequireMFAState() RequireMFAState {
	switch {
	case s.RequireMFAUpgradeGrace:
		return RequireMFAGraceNotEnforced
	case !s.RequireMFA:
		return RequireMFAOff
	case s.RequireMFAImplicitDefault:
		return RequireMFAEnforcingImplicit
	default:
		return RequireMFAEnforcingExplicit
	}
}

// Weakened reports whether the state is below ADR-112's baseline. Fails closed:
// anything but the two enforcing states counts.
func (st RequireMFAState) Weakened() bool {
	return st != RequireMFAEnforcingImplicit && st != RequireMFAEnforcingExplicit
}
