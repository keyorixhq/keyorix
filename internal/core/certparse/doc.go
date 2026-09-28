// Package certs holds core's pure X.509 leaf-certificate selection logic:
// parseLeafCertificate and selectLeafCertificate (ADR-054's certificate
// inspection feature). Neither performs I/O — both operate on a
// caller-supplied byte value.
//
// It exists so parseLeafCertificate can be fuzzed cheaply. Go's fuzzer
// tracks coverage over every package the test binary links, and each input
// costs several passes over that coverage map. A fuzz target in package core
// links core's whole dependency tree; the same target here links only the
// standard library, and runs many times more inputs per second (see
// internal/core/rules' doc.go for the measured shape of this effect
// elsewhere in this codebase).
//
// Rules for this package:
//   - It must stay a leaf: it may import only the standard library — nothing
//     else from this module. TestCertparseStaysALeaf enforces this.
//   - Package core keeps its public API via a thin wrapper function
//     (core/certificate.go), so callers don't change.
package certparse
