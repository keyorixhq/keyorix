package fuzzworld

import "strings"

// PGText makes a fuzzer-supplied string storable in a PostgreSQL text column.
// PostgreSQL refuses invalid UTF-8 (for example "\xad") and NUL (0x00) with
// SQLSTATE 22021, while SQLite stores both. A harness that seeds such a string
// through the world's DB fails the iteration at setup, before the code under
// test runs: a false positive that was once closed as "flaky" (fuzz-corpus#194,
// keyorix#4754). Invalid UTF-8 becomes U+FFFD and NUL is dropped; valid input is
// returned unchanged, and the result is idempotent.
//
// Use it only on values a harness writes as its OWN setup (seed rows, canary
// payloads, passphrases stored beside the data) and then checks its oracles
// against the returned value, so the checks stay exact.
//
// What this does NOT verify: it hides invalid-byte and NUL inputs from PG
// seeding. A product bug that fires only when such a string is stored is not
// exercised through a normalised seed. Do not apply it to a fuzzer string that is
// itself the product input under test (a request body, a ref, a query value):
// there the PG refusal is a product observable, and the harness must classify
// it, not hide it (see the NUL-INVALID-UTF8 entry in
// internal/storage/store/storage_iface_differential_fuzz_test.go and
// isPGTextEncodingReject in gorm_tenant_isolation_fuzz_test.go). It does not
// bound length (PostgreSQL's btree row limit is a separate refusal) and does not
// touch bytea or []byte columns, which accept arbitrary bytes.
func PGText(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
}
