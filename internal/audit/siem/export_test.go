package siem

// IsDisallowedIPForFuzz exports isDisallowedIP for FuzzSSRFGuardDifferential
// (internal/core/ssrf_guard_differential_fuzz_test.go), which drives this
// package's REAL dial-time SSRF policy from a single cross-package
// differential harness alongside netutil's and internal/core's own guards —
// the same "export the real logic for an external parity checker" shape
// netutil.EmbeddedIPv4 already establishes.
//
// Was previously an exported func in forwarder.go (production code); moved
// here (a Go test-only compilation unit — never linked into a production
// build or any binary that imports this package) since no production caller
// should ever be able to reach a hook whose only purpose is letting an
// external test drive this package's internal policy directly. newForwarder
// already wires isDisallowedIP itself, not this export.
//
// This is a Go test-only file: only siem's own `go test` build includes it,
// so a cross-package test importing siem as an ordinary dependency (as
// internal/core's FuzzSSRFGuardDifferential does) can no longer resolve this
// symbol the way it could when it was an ordinary exported func in
// forwarder.go. That fuzz test's own call site needs to change as a result
// (e.g. moving the differential check itself into this package, or a
// different cross-package parity mechanism) — out of scope here.
var IsDisallowedIPForFuzz = isDisallowedIP
