// Package anchorbundle holds internal/auditverify's pure parser for the
// design §3 `--anchor` bundle: ExternalAnchorBundle and
// ParseExternalAnchorBundle. It performs no I/O — it only decodes JSON bytes
// the caller already read off disk.
//
// It exists so ParseExternalAnchorBundle can be fuzzed cheaply. Go's fuzzer
// tracks coverage over every package the test binary links, and each input
// costs several passes over that coverage map. A fuzz target in package
// auditverify links auditverify's whole dependency tree (internal/notary,
// pulled in only for crossCheckExternalAnchor's RFC 3161 verification, which
// ParseExternalAnchorBundle never calls); the same target here links only the
// standard library, and runs many times more inputs per second (see
// internal/core/rules' doc.go for the measured shape of this effect elsewhere
// in this codebase).
//
// Rules for this package:
//   - It must stay a leaf: it may import only the standard library — nothing
//     else from this module. TestAnchorBundleStaysALeaf enforces this.
//   - Package auditverify keeps its public API via type aliases and a thin
//     wrapper function (auditverify/anchor_bundle.go), so callers don't
//     change.
package anchorbundle
