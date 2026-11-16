//go:build !e2e

// This file exists so the MP1 fuzz targets are DISCOVERABLE by
// `go test -list '^Fuzz' ./...` (the form CI's fuzz-targets job runs, with no
// build tags) even though their real implementations live behind the `e2e`
// tag. Without this, scripts/fuzzing/targets.d entries for FuzzMP1MultiProc /
// FuzzMP1UniqueCreate would be reported as stale (declared but not listable),
// turning the fuzz-targets guard red. The stubs skip immediately: the real
// multi-process harness needs the `e2e` tag AND a PostgreSQL DSN, which a
// tag-less rig run does not have. The real bodies are the identically-named
// functions in cluster_fuzz_test.go and uniqueness_test.go (both `//go:build
// e2e`), selected instead of these stubs whenever the tag is set.
package mp1

import "testing"

func FuzzMP1MultiProc(f *testing.F) {
	f.Skip("MP1 multi-process harness requires -tags e2e and KEYORIX_TEST_PG_DSN")
}

func FuzzMP1UniqueCreate(f *testing.F) {
	f.Skip("MP1 multi-process harness requires -tags e2e and KEYORIX_TEST_PG_DSN")
}
