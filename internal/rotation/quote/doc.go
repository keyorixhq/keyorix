// Package quote holds internal/rotation's pure SQL-quoting and upstream-ref
// validation rules: functions that take plain values and return a verdict or
// an escaped string, with no network I/O, no DB connection, and no cloud SDK.
//
// It exists so these rules can be fuzzed cheaply. Go's fuzzer tracks coverage
// over every package the test binary links, and each input costs several
// passes over that coverage map. A fuzz target in package rotation links
// rotation's whole dependency tree (pgx, the MySQL driver, the Azure token
// source seam); the same target here links only the standard library, and
// runs many times more inputs per second (see internal/core/rules' doc.go for
// the measured shape of this effect elsewhere in this codebase).
//
// Rules for this package:
//   - It must stay a leaf: it may import only the standard library — nothing
//     else from this module. TestQuoteStaysALeaf enforces this.
//   - Package rotation keeps its public API via thin wrapper functions
//     (rotation/quote_compat.go), so callers don't change.
package quote
