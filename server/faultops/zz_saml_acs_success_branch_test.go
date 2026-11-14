// zz_saml_acs_success_branch_test.go — SAML-TAILS-1 items 3 and 4, the harness
// half of #2934 (a) and the four SUCCESS-branch diffs of #2839 item 2, on the
// SAML ACS op (zz_saml_acs_op_test.go).
//
// Both no longer reproduce on main. #2934 (a) was a random fixture subject (and
// the session's ip:port, #2919): every success-branch fault differed from the
// reference world in User/Session/AuditEvent whatever the fault did. #2910 made
// the subject and RelayState deterministic; these tests keep that true:
//
//   - TestSAMLACSOp_OracleASeesAPerWorldSubject is the calibration: with a
//     per-world subject swapped in, the same four tuples are oracle (a)
//     findings again (the #2934 false positive), with the deterministic one they
//     are not. That is the before/after count, and the proof that the oracle can
//     still see a User difference here, so the first test is not green because
//     the oracle went blind.
package faultops

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const samlACSOpKey = "REST POST /auth/saml/{provider}/acs"

// samlACSIssueSuccessFaults are the four SUCCESS-branch diffs #2839 item 2
// reported on this op, every one a best-effort step after the session commit.
var samlACSIssueSuccessFaults = []struct {
	method string
	nth    int
}{
	{"EnforceSessionLimit", 1},
	{"LogAuditEvent", 1},
	{"LogAuditEvent", 2},
	{"UpdateLastLogin", 1},
}

// driveSAMLACSFindings runs one (method, nth, KindError) case on the SAML ACS op
// with a fresh world pair and returns what the oracles concluded: the input they
// saw and every violation they would have failed on. A case that did not reach
// the oracle fails the test: a tuple that cannot be exercised cannot be shown
// to pass.
func driveSAMLACSFindings(t *testing.T, method string, nth int) (oracleInput, []string) {
	t.Helper()
	opIdx := slices.IndexFunc(opCatalog, func(o operation) bool { return o.Key == samlACSOpKey })
	methodIdx := slices.Index(storageInterfaceMethodNames(), method)
	if opIdx < 0 || methodIdx < 0 {
		t.Fatalf("op %q index %d, method %q index %d", samlACSOpKey, opIdx, method, methodIdx)
	}
	data := []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), fuzzKindSelector(faultstorage.KindError)}
	var seen oracleInput
	got := false
	sink := &driveSink{t: t}
	func() {
		defer func() { rethrowUnlessDriveAbort(recover()) }()
		runOneFuzzIterationReporting(t, sink, data, nil, nil, func(in oracleInput) { seen, got = in, true })
	}()
	if sink.notEvaluated != "" {
		t.Fatalf("%s#%d: not evaluated: %s", method, nth, sink.notEvaluated)
	}
	if !got {
		t.Fatalf("%s#%d never fired during %s: the tuple no longer exercises this op", method, nth, samlACSOpKey)
	}
	return seen, sink.findings
}

func oracleAFindings(findings []string) int {
	n := 0
	for _, f := range findings {
		if strings.Contains(f, "ORACLE (a)") {
			n++
		}
	}
	return n
}

// Item 3, before/after: the oracle (a) count on these four tuples with a
// per-world subject (the #2934 fixture) and with the deterministic one.
func TestSAMLACSOp_OracleASeesAPerWorldSubject(t *testing.T) {
	// Each case in its own subtest, so its worlds close when it ends.
	count := func(mode string) int {
		n := 0
		for _, c := range samlACSIssueSuccessFaults {
			t.Run(fmt.Sprintf("%s/%s#%d", mode, c.method, c.nth), func(t *testing.T) {
				_, findings := driveSAMLACSFindings(t, c.method, c.nth)
				if oracleAFindings(findings) > 0 {
					n++
				}
			})
		}
		return n
	}

	orig := fuzzSAMLSubject
	var worlds atomic.Int64
	fuzzSAMLSubject = func() string { return fmt.Sprintf("fuzz-saml-world-%d", worlds.Add(1)) }
	before := func() int {
		defer func() { fuzzSAMLSubject = orig }()
		return count("per-world-subject")
	}()
	after := count("deterministic-subject")

	t.Logf("SAML ACS oracle (a) findings on the %d #2839 success-branch tuples: per-world subject %d, deterministic subject %d",
		len(samlACSIssueSuccessFaults), before, after)
	if before != len(samlACSIssueSuccessFaults) {
		t.Errorf("calibration: a per-world subject must make every success-branch tuple an oracle (a) finding (got %d of %d): the oracle no longer compares the account",
			before, len(samlACSIssueSuccessFaults))
	}
	if after != 0 {
		t.Errorf("deterministic subject: %d of %d tuples are still oracle (a) findings", after, len(samlACSIssueSuccessFaults))
	}
}
