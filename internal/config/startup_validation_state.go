package config

// StartupValidationState is what security.enable_file_permission_check
// actually does on this boot (#2908). A boolean cannot say it: during
// ADR-112's upgrade grace period the field reads true while the server only
// WARNS about a failed startup check instead of refusing to start, and a
// boolean "skipped?" reported that deployment as clean in the start-up
// warning, the settings diff and the posture report alike.
//
// The values are the settings-diff Value of the
// security.insecure_skip_startup_validation registry entry, so each must stay
// distinct: a transition between any two is a security-relevant change the
// start-to-start diff has to audit.
type StartupValidationState string

const (
	// StartupValidationOff: enable_file_permission_check: false is written in
	// the config file. ValidateStartup is skipped and key-file permissions only
	// warn. In effect (a deviation).
	StartupValidationOff StartupValidationState = "off"
	// StartupValidationGraceWarnOnly: the key is absent and this boot is an
	// upgraded deployment inside ADR-112's grace period
	// (EnableFilePermissionCheckUpgradeGrace): the checks run, but a failure is
	// logged as a warning and the server starts anyway. In effect (a
	// deviation) -- the third state #2908 adds.
	StartupValidationGraceWarnOnly StartupValidationState = "grace-warn-only"
	// StartupValidationEnforcingImplicit: the key is absent and the deployment
	// is enforced (a fresh install, or one already ratcheted past the grace
	// period by the adr112.file_permission_check.enforced marker). A failed
	// check refuses to start. Not in effect: this is ADR-112's default, and the
	// ADR requires the posture report to show zero deviations for it.
	StartupValidationEnforcingImplicit StartupValidationState = "enforcing-implicit"
	// StartupValidationEnforcingExplicit: enable_file_permission_check: true is
	// written in the config file. Not in effect.
	StartupValidationEnforcingExplicit StartupValidationState = "enforcing-explicit"
)

// StartupValidationState derives the state from the fields Load() and
// server/main.go's applyADR112UpgradeGrace set. It follows what the boot path
// DOES rather than how the fields are meant to be combined: runStartupValidation
// and enforceKeyFilePermissions soften on EnableFilePermissionCheckUpgradeGrace
// alone, so that flag selects the grace state whatever ImplicitDefault says (a
// hand-built *Config cannot read as enforcing while the boot path would warn).
func (s *SecurityConfig) StartupValidationState() StartupValidationState {
	switch {
	case !s.EnableFilePermissionCheck:
		return StartupValidationOff
	case s.EnableFilePermissionCheckUpgradeGrace:
		return StartupValidationGraceWarnOnly
	case s.EnableFilePermissionCheckImplicitDefault:
		return StartupValidationEnforcingImplicit
	default:
		return StartupValidationEnforcingExplicit
	}
}

// Weakened reports whether the state is below ADR-112's baseline: off, or
// warn-only in the grace period. Fails closed: anything but the two enforcing
// states counts, so a state added later is a deviation until someone decides
// otherwise.
func (st StartupValidationState) Weakened() bool {
	return st != StartupValidationEnforcingImplicit && st != StartupValidationEnforcingExplicit
}
