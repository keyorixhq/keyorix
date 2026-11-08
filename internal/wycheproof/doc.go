// Package wycheproof runs Project Wycheproof test vectors (github.com/C2SP/wycheproof,
// testvectors_v1, pinned by commit and SHA-256) against the cryptographic
// wrappers Keyorix owns and the third-party verifiers it relies on, and
// mutates every valid vector to check that tampered inputs are refused.
//
// The rules the suites enforce are written down in RULES.md. The package has
// no non-test code of its own; the vector loader lives in wvec. Fetch the
// vectors with scripts/wycheproof/fetch.sh; without them the vector tests skip
// (set WYCHEPROOF_REQUIRE=1 to make that a failure).
package wycheproof
