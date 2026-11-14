// Package cloudfuzz provides shared scaffolding for the hostile-SERVER fuzz
// harnesses against the CLOUD SDKs Keyorix drives against operator-/attacker-
// influenceable endpoints: aws-sdk-go-v2 (KMS, S3, STS, IAM), azure-sdk-for-go
// (azkeys), and the wneessen/go-mail SMTP client.
//
// Threat model (identical to fuzz/thirdparty's DB-driver harnesses): Keyorix is
// the CLIENT; the endpoint it talks to is attacker-influenced — either because
// the operator can point a KMS/S3/vault/SMTP endpoint at an arbitrary host
// (evidencesink object store, connect connectors, SMTP relay) or because an
// on-path attacker can MITM a cloud endpoint. The server replies with
// grammar-aware mutated bodies (JSON for awsjson/azure REST, XML for S3
// rest-xml, an SMTP dialogue for go-mail), wrong content-types, truncated or
// over-large bodies, redirects. These harnesses drive the REAL SDK client (as
// the Keyorix caller drives it), through the SDK's own documented endpoint/
// transport override, against a loopback server whose replies are
// fuzzer-controlled, and assert sound oracles.
//
// This package deliberately does NOT reuse internal/connect's response fuzzers
// (FuzzAWSSMConnectorResponse / FuzzAzureKVConnectorResponse /
// FuzzGCPSMConnectorResponse / FuzzVaultConnectorResponse): those already cover
// the federated-secret GetSecret path. The targets here cover the DISJOINT
// surface — KMS wrap/unwrap, S3 rest-xml, STS/IAM, and the SMTP dialogue — that
// no existing harness drives.
//
// Shared oracles (sound only), each exposed as a helper below:
//   - Panic: no panic escapes the SDK's documented error path (RunGuarded).
//   - Bounded time: each call returns within a deadline (RunGuarded via
//     fuzzutil.Guard — a hang or memory-amplification bomb trips it).
//   - No goroutine / fd leak once the call has returned (CheckNoLeak).
//   - No secret material (the credential the client SENT) in any error string
//     (AssertNoSecretInError).
//
// What these oracles do NOT verify is stated per target, in each target file's
// package doc, not here.
package cloudfuzz

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func init() {
	// Resource hygiene on the shared fuzz host (see task runtime rules): cap the
	// scheduler thread count from inside the test binary, since the equivalent
	// GOMAXPROCS=2 environment override is not available in this sandbox. -parallel
	// bounds fuzz workers; this bounds the runtime's P count underneath them.
	if runtime.GOMAXPROCS(0) > 2 {
		runtime.GOMAXPROCS(2)
	}
}

// LeakCeiling is the generous absolute goroutine/fd ceiling. Steady state for a
// single SDK client is O(10-20); crossing this means a per-input leak is
// accumulating across the fuzz worker's inputs, not a single teardown transient.
// Mirrors internal/connect's connectLeakCeiling.
const LeakCeiling = 1000

// RunGuarded runs fn under fuzzutil.Guard (panic propagates to the fuzzer
// natively; a hang or amplification bomb trips the wall-clock deadline and is
// reported via t.Fatalf so the input is saved). label names the call under test.
func RunGuarded(t *testing.T, label string, fn func()) {
	t.Helper()
	fuzzutil.Guard(t.Fatalf, label, fn)
}

// CheckNoLeak asserts the process has not accumulated goroutines or file
// descriptors past LeakCeiling after a guarded call returned. It first lets
// transient teardown goroutines settle (a closed idle HTTP connection's reader
// goroutine, a dial that lost a race) — an absolute ceiling, not a delta, so a
// brief settle is enough and no exact baseline is needed.
func CheckNoLeak(t *testing.T, label string) {
	t.Helper()
	settleBelow(LeakCeiling)
	if n := runtime.NumGoroutine(); n > LeakCeiling {
		t.Fatalf("goroutine leak: %d goroutines after %s (ceiling %d)", n, label, LeakCeiling)
	}
	if fd := openFDCount(); fd > LeakCeiling {
		t.Fatalf("fd leak: %d open descriptors after %s (ceiling %d)", fd, label, LeakCeiling)
	}
}

// settleBelow waits briefly for the live goroutine count to fall under ceiling,
// giving transient teardown goroutines a chance to exit before the hard check.
func settleBelow(ceiling int) {
	for range 20 {
		if runtime.NumGoroutine() <= ceiling {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// openFDCount returns the number of open file descriptors on Linux (the fuzz
// rigs), or -1 elsewhere. Mirrors internal/connect's connectOpenFDCount.
func openFDCount() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// AssertNoSecretInError fails if any of secrets appears verbatim in err's
// string. secrets are the credential/token values the CLIENT sent (a static AWS
// access-key id, an SMTP password, a bearer token) — NOT response-body content,
// which is attacker-chosen and legitimately may be echoed. An empty secret is
// ignored (a substring check for "" matches everything). label names the call.
func AssertNoSecretInError(t *testing.T, label string, err error, secrets ...string) {
	t.Helper()
	scanSecretsInError(t.Fatalf, label, err, secrets...)
}

// scanSecretsInError is the testable core of AssertNoSecretInError: it takes a
// fatalf callback (pass t.Fatalf, or a capturing fake in the oracle self-test) so
// the oracle can be red/green-proven without a real *testing.T.
func scanSecretsInError(fatalf func(format string, args ...any), label string, err error, secrets ...string) {
	if err == nil {
		return
	}
	msg := err.Error()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(msg, s) {
			fatalf("LEAK: a sent credential appeared in the error returned by %s: %v", label, err)
			return
		}
	}
}

// ClampHTTPStatus maps an arbitrary fuzzer int onto a valid FINAL HTTP status
// (200-599; 1xx excluded — see internal/connect's clampHTTPStatus for why a bare
// 1xx has no meaningful final-status reading and must not be clamped INTO range).
// An already-valid [200,599] passes through unchanged so a seed's literal status
// is sent verbatim.
func ClampHTTPStatus(v int) int {
	if v >= 200 && v <= 599 {
		return v
	}
	if v < 0 {
		v = -v
	}
	return 200 + (v % 400)
}
