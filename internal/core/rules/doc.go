// Package rules holds core's pure validation and encoding rules: functions
// that take plain values and return a verdict, with no storage, no network,
// no clock and no connector.
//
// It exists so that these rules can be fuzzed cheaply. Go's fuzzer tracks
// coverage over every package the test binary links, and each input costs
// several passes over that coverage map. A fuzz target in package core links
// core's whole dependency tree (every connector SDK), about 480 KB of map; the
// same target here links ~5-20 KB, and runs 18-25x more inputs per second
// with minimization stalls gone (Keyorix project doc
// claude/2026-09-23-coverage-map-leaf-package-ab-results.md).
//
// Rules for this package:
//   - It must stay a leaf: it may import the standard library and
//     internal/storage/models, nothing else from this module (in particular
//     not internal/core, internal/i18n, storage, or any connector).
//     TestRulesStaysALeaf enforces this.
//   - Package core keeps its public API via type aliases and thin wrappers
//     (core/rules_compat.go), so callers don't change.
package rules
