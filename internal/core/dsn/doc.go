// Package dsn holds core's pure DSN host-extraction rules (ADR-035 dynamic
// secrets): given an admin_dsn string in any of the formats core recognizes
// (URL, MySQL tcp()/() wrapper, PostgreSQL key-value, Kubernetes JSON blob),
// extract every host it names. None of it performs I/O — it operates
// entirely on the caller-supplied string. validateAdminDSNHost
// (internal/core/dynamic_secrets.go) stays in package core: it calls
// net.LookupHost for a non-literal host, genuine DNS I/O this package
// deliberately does not perform.
//
// It exists so ParseDSNHosts and its callers can be fuzzed cheaply. Go's
// fuzzer tracks coverage over every package the test binary links, and each
// input costs several passes over that coverage map. A fuzz target in
// package core links core's whole dependency tree; the same target here
// links only the standard library, and runs many times more inputs per
// second (see internal/core/rules' doc.go for the measured shape of this
// effect elsewhere in this codebase).
//
// Rules for this package:
//   - It must stay a leaf: it may import only the standard library — nothing
//     else from this module. TestDSNStaysALeaf enforces this.
//   - Package core keeps its public API via thin wrapper functions
//     (core/dynamic_secrets.go), so callers don't change.
package dsn
