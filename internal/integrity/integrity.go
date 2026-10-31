// Package integrity reports the host's boot and binary integrity signals as
// ADVISORY, SELF-REPORTED posture lines (RD-INTEG-POSTURE-1, RD-TIER-POSTURE-1).
//
// Everything here is read by the process being judged, from the host it runs
// on. A compromised host can answer every question below "ok", so a line from
// this package is a visibility aid, never evidence: proof needs a verifier
// outside the host, which is TPM remote attestation (ADR-117, ADR-119).
// Every rendered line therefore carries Label, and
// TestEveryLineCarriesTheAdvisoryLabel keeps it so.
//
// Nothing in this package refuses, blocks or changes an exit code. An
// unreadable source is StateUnknown, never StateOK.
package integrity

import (
	"fmt"
	"runtime"
	"strings"
)

// Label is appended to every rendered line. Do not reword it without updating
// docs/security/integrity-posture.md and the calibration tests.
const Label = "advisory (self-reported)"

// DocsPath is the page that explains each line and the tier table.
const DocsPath = "docs/security/integrity-posture.md"

// State is what one check found.
type State string

const (
	// StateOK: the source was read and shows the protective state.
	StateOK State = "ok"
	// StateOKQualified: the source was read and looks protective, but a caveat
	// (Line.Qualifier) means the claim is not established. It renders as
	// "ok (<qualifier>)" and is NOT StateOK, so a tier rung never counts it.
	StateOKQualified State = "ok (qualified)"
	// StateDegraded: the source was read and shows the protection is absent.
	StateDegraded State = "degraded"
	// StateUnknown: the source could not be read or understood. Never "ok".
	StateUnknown State = "unknown"
	// StateNotApplicable: this OS has no such mechanism (anything but Linux).
	StateNotApplicable State = "not applicable"
	// StateNotChecked: nothing to compare against (no local release manifest).
	StateNotChecked State = "not checked"
)

// Check ids, one per line.
const (
	CheckSecureBoot = "secure-boot"
	CheckLockdown   = "kernel-lockdown"
	CheckIMA        = "ima"
	CheckFSVerity   = "fs-verity"
	CheckManifest   = "release-manifest"
	CheckTPMSealing = "tpm-sealing"
	CheckKeylime    = "keylime-agent"
)

// Line is one posture line.
type Line struct {
	ID     string
	State  State
	Detail string
	// Qualifier is the caveat shown for StateOKQualified, e.g.
	// "signature not verified".
	Qualifier string
}

// String renders the line. The label is part of the line, not a footnote.
func (l Line) String() string {
	state := string(l.State)
	if l.State == StateOKQualified {
		state = "ok (" + l.Qualifier + ")"
	}
	return fmt.Sprintf("integrity/%s: %s — %s [%s; see %s]", l.ID, state, l.Detail, Label, DocsPath)
}

// TPMState is what the TPM key provider's configuration exposes. It is read,
// never changed: internal/crypto/tpm_provider.go is not touched.
type TPMState struct {
	// Configured: storage.encryption.key_provider.type is "tpm".
	Configured bool
	// BlobPresent: the sealed KEK blob exists at the configured path.
	BlobPresent bool
	// BlobErr: the blob could not be examined (anything but not-exist).
	BlobErr error
}

// FSVerity reports whether fs-verity is enabled on a file. It is an interface
// so tests fake the ioctl.
type FSVerity interface {
	Enabled(path string) (bool, error)
}

// Env is everything Collect reads from the host. The zero value of each
// injectable field selects the real implementation.
type Env struct {
	// Root is the filesystem root the /sys and /proc reads are resolved
	// under. Empty means "/". Tests point it at a fake tree.
	Root string
	// GOOS defaults to runtime.GOOS. Anything but "linux" yields
	// StateNotApplicable for the Linux-only lines.
	GOOS string
	// Executable returns the running binary's path (default os.Executable).
	Executable func() (string, error)
	// FSVerity defaults to the platform implementation.
	FSVerity FSVerity
	// TPM is the TPM provider state.
	TPM TPMState
	// KeylimePresent reports whether a Keylime agent runs on this host
	// (default: scans <Root>/proc/*/comm).
	KeylimePresent func() (bool, error)
}

// Report is the lines plus the detected tier.
type Report struct {
	Lines []Line
	Tier  int
	// TierWhy says which rung stopped the climb.
	TierWhy string
}

// Strings renders the lines and the tier line, ready for report.info.
func (r Report) Strings() []string {
	out := make([]string, 0, len(r.Lines)+1)
	for _, l := range r.Lines {
		out = append(out, l.String())
	}
	out = append(out, fmt.Sprintf("integrity/tier: %d of %d (detected, informational — never affects /health, startup or any exit code; %s) [%s; see %s]",
		r.Tier, MaxTier, r.TierWhy, Label, DocsPath))
	return out
}

// Collect runs every check. It never fails: a check that cannot answer says so.
func Collect(env Env) Report {
	env = env.withDefaults()
	lines := []Line{
		checkSecureBoot(env),
		checkLockdown(env),
		checkIMA(env),
		checkFSVerity(env),
		checkManifest(env),
		checkTPM(env),
		checkKeylime(env),
	}
	tier, why := DetectTier(lines)
	return Report{Lines: lines, Tier: tier, TierWhy: why}
}

func (e Env) withDefaults() Env {
	if e.Root == "" {
		e.Root = "/"
	}
	if e.GOOS == "" {
		e.GOOS = runtime.GOOS
	}
	if e.Executable == nil {
		e.Executable = defaultExecutable
	}
	if e.FSVerity == nil {
		e.FSVerity = platformFSVerity{}
	}
	if e.KeylimePresent == nil {
		root := e.Root
		e.KeylimePresent = func() (bool, error) { return keylimeInProc(root) }
	}
	return e
}

func (e Env) linux() bool { return strings.EqualFold(e.GOOS, "linux") }

func notApplicable(id, what string) Line {
	return Line{ID: id, State: StateNotApplicable, Detail: what + " is a Linux mechanism; this host is not Linux"}
}
