package connect

// connect_fuzz_helpers_test.go — small helpers shared by the per-backend
// response-fuzzing targets (vault_response_fuzz_test.go, awssm_response_fuzz_test.go,
// azurekv_response_fuzz_test.go, gcpsm_response_fuzz_test.go). Each target builds a
// fake backend endpoint whose HTTP status (or gRPC code) is derived from a fuzzer-
// supplied int, and checks for a goroutine leak after each call — mirroring the
// pattern already established in internal/notary/notary_fuzz_test.go.

import (
	"os"
	"runtime"
)

// clampHTTPStatus maps an arbitrary fuzzer-supplied int onto a valid FINAL HTTP
// status code (200-599; deliberately excludes 1xx). net/http's
// ResponseWriter.WriteHeader panics on an out-of-range code, so the raw fuzzer
// int can't be written directly.
//
// An already-valid [200,599] value passes through UNCHANGED -- not folded via
// modulo -- so a seed's literal f.Add(..., 403, ...) really does send 403, not
// some unrelated remapped code. An earlier version of this function remapped
// every value through `100 + (v % 500)` unconditionally, which silently turned
// EVERY seed's intended status (200, 403, 500, 301, ...) into a different,
// arbitrary code (e.g. 301 became 401) -- every seed exercised some valid-but-
// unintended status, never the one its own literal value or comment described.
// Only a genuinely out-of-range fuzzer-mutated value (negative, or >= 600) needs
// remapping at all.
//
// 1xx is excluded, not clamped into, for a reason confirmed by reading
// net/http/server.go's WriteHeader directly (not assumed): for any code in
// [100,199] except 101, WriteHeader sends it as a genuine RFC 9110 informational
// response and does NOT mark the response written -- a handler's subsequent
// Write(body) then triggers Write's own documented fallback of an IMPLICIT
// WriteHeader(200). So a fake handler that calls WriteHeader(180) followed by
// Write(body) never actually sends 180 as a final status at all; the real
// final status on the wire is 200, and a correct HTTP client reads it as such.
// An earlier version of this harness clamped into [100,599] and got exactly
// this: status 180 "bypassing" the non-200 fail-closed check -- not a Keyorix
// defect, a false positive from asking net/http's ResponseWriter to do
// something HTTP's own 1xx semantics don't allow it to do (a bare 1xx has no
// meaningful "final status" reading; that's what interim means).
func clampHTTPStatus(v int) int {
	if v >= 200 && v <= 599 {
		return v
	}
	if v < 0 {
		v = -v
	}
	return 200 + (v % 400)
}

// connectOpenFDCount returns the number of open file descriptors for this process
// on Linux (the fuzz rigs), or -1 elsewhere (macOS dev has no /proc) -- callers
// skip the fd-leak check in that case. Mirrors internal/notary/notary_fuzz_test.go's
// openFDCount.
func connectOpenFDCount() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// connectLeakCeiling is the generous absolute goroutine/fd ceiling used by every
// response-fuzzing target below -- steady state is O(10-20) per backend client;
// crossing this indicates a per-input leak accumulating across the fuzz worker's
// inputs, not a single input's transient teardown.
const connectLeakCeiling = 1000

// connectRetryCeiling bounds how many times a single GetSecret call may hit the
// fake backend server/service, regardless of what status/code/Retry-After it
// sends back. Each backend's own configured retry bound is much smaller (Vault:
// 1, no retry logic at all; AWS: RetryMaxAttempts; Azure: MaxRetries+1; GCP:
// bounded structurally by the short context deadline, not attempt count) -- this
// is deliberately a generous ceiling ABOVE all of them (a "no retry storm"
// tripwire), not a precise per-backend attempt-count assertion, so it stays
// sound even if an individual backend's own retry-classification logic (which
// status codes are "retryable") differs from what a naive reading would predict.
const connectRetryCeiling = 10
