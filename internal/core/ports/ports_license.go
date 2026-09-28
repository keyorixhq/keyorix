// ports_license.go — the LicenseGate seam (ADR-109 "last decoupling", B5):
// internal/core's only remaining direct use of internal/license was a thin
// re-export of pkg/licenseverify (see internal/license/license.go's own doc
// comment: "re-exports pkg/licenseverify's offline license API ... so the
// server (Gate) and the old CLI ... keep compiling unchanged" — every symbol
// there is the SAME code as pkg/licenseverify's, not a duplicate). Since
// pkg/licenseverify is already the public, no-cloud-SDK, no-internal/core-
// core-dependency leaf package ADR-108's CLI split created specifically so
// the separate cli/ module could use it, internal/core/ports aliases
// straight to it — no adapter needed, and internal/core now imports
// internal/core/ports instead of internal/license entirely.
package ports

import "github.com/keyorixhq/keyorix/pkg/licenseverify"

// LicenseState mirrors pkg/licenseverify.State (internal/core/license_expiry.go
// switches on it).
type LicenseState = licenseverify.State

// LicenseStatus mirrors pkg/licenseverify.Status, the return type of
// LicenseGate.Status() (internal/core/service.go's LicenseStatus method,
// internal/core/license_expiry.go's severity/notice helpers).
type LicenseStatus = licenseverify.Status

const (
	LicenseStateActive       = licenseverify.StateActive
	LicenseStateExpiringSoon = licenseverify.StateExpiringSoon
	LicenseStateExpired      = licenseverify.StateExpired
	// LicenseStateNone is the community-baseline state internal/core reports
	// itself (KeyorixCore.LicenseStatus) when no LicenseGate is wired — the
	// same state *licenseverify.Gate's own nil-receiver Status() used to
	// report before this interface-typed field existed (see LicenseGate's
	// own doc comment for why a nil check moved to the call site).
	LicenseStateNone = licenseverify.StateNone

	// FeatureBilling gates billing reports behind a commercial license
	// (internal/core/billing.go).
	FeatureBilling = licenseverify.FeatureBilling
)

// LicenseGate resolves whether a commercial feature is licensed, and the
// license's own status. A type alias would work here too (*licenseverify.Gate
// has no other exported dependents inside internal/core beyond these two
// methods), but an interface is used instead — matching
// ConnectorResolver/RotationExecutorResolver's own shape — so a nil
// LicenseGate (SetLicenseGate never called) is a normal, checkable "no gate
// wired" state for internal/core, rather than a nil *licenseverify.Gate
// pointer whose methods would need their own nil-receiver handling.
type LicenseGate interface {
	Status() LicenseStatus
	HasFeature(feature string) bool
}
