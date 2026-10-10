// tolerance_dump_test.go — exports knownOpenTolerances as TSV so a CI script
// can check each row's cited issue is still OPEN (#2844 (b)).
//
// Why a test and not a generator. knownOpenTolerances lives in a _test.go file
// (it is harness configuration, not product code), so no `go run` target can
// reach it. Exporting it from a test, gated on an env var, is the standard Go
// idiom for exactly this.
//
// Why a separate script and not an assertion in the test. Checking issue state
// needs the GitHub API, and a unit test must not reach the network: it would be
// flaky offline, slow in every local run, and would make `go test ./...` depend
// on a credential. So the DATE check lives in
// TestKnownOpenTolerances_CarryIssueAndExpiry (pure, offline, deterministic) and
// the STATE check lives in scripts/check-fault-tolerance-issues.sh as its own CI
// step. The two are complementary, not redundant: the date is a backstop for
// when the API is unavailable, the state is the signal that actually matters.
package faultops

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// toleranceDumpEnv names the file to write the TSV to. Unset (the normal case)
// makes this test a no-op.
const toleranceDumpEnv = "KEYORIX_TOLERANCE_DUMP"

// TestDumpKnownOpenTolerances writes one TSV line per tolerance:
//
//	label \t issue \t expires \t wildcards
//
// It is a data export, not a check — hence the skip when the env var is unset.
// That skip is safe in a way a check's skip would not be: nothing concludes
// anything from this test passing. The consumer
// (scripts/check-fault-tolerance-issues.sh) fails if the file it asked for does
// not appear, so a silently-skipped dump cannot read as "no rows to check".
func TestDumpKnownOpenTolerances(t *testing.T) {
	path := os.Getenv(toleranceDumpEnv)
	if path == "" {
		t.Skipf("%s is unset — this test exports data for scripts/check-fault-tolerance-issues.sh and "+
			"asserts nothing; set it to a file path to produce the dump", toleranceDumpEnv)
	}
	var b strings.Builder
	for _, k := range knownOpenTolerances {
		label := fmt.Sprintf("%s/%s/%s#%d", k.op, k.method, k.kind, k.nth)
		wild := strings.Join(toleranceWildcardedDimensions(k), "+")
		if wild == "" {
			wild = "-"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", label, k.issue, k.expires, wild)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing tolerance dump to %s: %v", path, err)
	}
	t.Logf("wrote %d tolerance row(s) to %s", len(knownOpenTolerances), path)
}
