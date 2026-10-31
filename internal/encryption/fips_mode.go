package encryption

import "crypto/fips140"

// FIPS140ModeLine is the `admin validate --posture` line that states which Go
// FIPS 140-3 mode this process runs in (the GODEBUG=fips140 setting). It reports
// the runtime mode only: it is not a statement that the build or the deployment
// is validated. Informational, never a deviation.
func FIPS140ModeLine() string {
	switch {
	case fips140.Enforced():
		return "Go FIPS 140-3 mode: enforced (GODEBUG=fips140=only)"
	case fips140.Enabled():
		return "Go FIPS 140-3 mode: on, not enforced (GODEBUG=fips140=on)"
	default:
		return "Go FIPS 140-3 mode: off"
	}
}
