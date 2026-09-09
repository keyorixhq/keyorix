// remote_support_doc_freshness_test.go — docs/REMOTE_CLI_SETUP.md and
// docs/CONFIGURATION.md both state, in prose, how much of remote mode is
// actually implemented ("197 of 426 RemoteStorage methods return
// ErrRemoteUnsupported"). A number written into a document is a claim, and
// this repository has three separate hand-maintained trackers -- BUGS.md,
// REMEDIATION-STATUS.md and adversarial-review/QUEUE.md -- that each went
// stale and each would have sent a reader to re-do already-finished work.
// The one status source that never went stale is the CI-enforced closure
// ledger, for exactly one reason: a build failure is not optional.
//
// So this test derives the two numbers from the source and fails when the
// documents stop matching. It fires in both directions, which is the point:
// implementing a stubbed method is GOOD and will fail this test, because
// the customer-facing statement about how complete remote mode is has just
// become wrong in the flattering direction. Update the docs; do not relax
// the test.
//
// See CLAUDE.md, "Core principle: prefer the machine-checked over the
// asserted."
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// remoteMethodRe matches a method declared on RemoteStorage (pointer or value
// receiver). Anchored at line start so it cannot match inside a comment body
// or a nested closure.
var remoteMethodRe = regexp.MustCompile(`(?m)^func \(.*RemoteStorage\) `)

// countRemoteSupport walks the remote_*.go files in this package's own
// directory (go test runs with cwd = the package dir) and returns the total
// number of RemoteStorage methods and how many of them are unimplemented
// stubs. Derived from source every run -- never from a stored constant, which
// would just be the same stale-claim problem one level down.
func countRemoteSupport(t *testing.T) (total, unsupported int) {
	t.Helper()
	matches, err := filepath.Glob("remote_*.go")
	if err != nil {
		t.Fatalf("globbing remote_*.go: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no remote_*.go files found -- this test's premise is broken, not satisfied")
	}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- fixed glob within the package dir
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		src := string(b)
		total += len(remoteMethodRe.FindAllString(src, -1))
		unsupported += strings.Count(src, "remoteUnsupported(")
	}
	return total, unsupported
}

// docClaim is one prose statement of the support numbers that must stay true.
type docClaim struct {
	path string
	re   *regexp.Regexp // must capture total and unsupported, in the order given by totalFirst
	// totalFirst reports whether capture group 1 is the total (else it is the
	// unsupported count) -- the two documents phrase the sentence in opposite
	// orders, and pinning the order here is cheaper than normalising the prose.
	totalFirst bool
	pct        bool // the sentence also states a percentage that must agree
}

var docClaims = []docClaim{
	{
		path:       filepath.Join("..", "..", "..", "docs", "REMOTE_CLI_SETUP.md"),
		re:         regexp.MustCompile(`of \*\*(\d+)\*\*\s*` + "`" + `RemoteStorage` + "`" + ` methods,\s*\n?> ?\*\*(\d+) \((\d+)%\)\*\*`),
		totalFirst: true,
		pct:        true,
	},
	{
		path:       filepath.Join("..", "..", "..", "docs", "CONFIGURATION.md"),
		re:         regexp.MustCompile(`(\d+) of (\d+)\s*` + "`" + `RemoteStorage` + "`" + `\s*\n?methods \((\d+)%\)`),
		totalFirst: false,
		pct:        true,
	},
}

// TestRemoteSupportDocsMatchCode is the guard described in this file's header.
func TestRemoteSupportDocsMatchCode(t *testing.T) {
	t.Parallel()

	total, unsupported := countRemoteSupport(t)
	if total == 0 {
		t.Fatal("derived 0 RemoteStorage methods -- the counting regex has stopped matching, " +
			"which would make this guard silently vacuous; fix remoteMethodRe rather than the docs")
	}
	wantPct := int(float64(unsupported) / float64(total) * 100.0)

	for _, c := range docClaims {
		b, err := os.ReadFile(c.path) // #nosec G304 -- fixed repo-relative doc paths
		if err != nil {
			t.Errorf("reading %s: %v", c.path, err)
			continue
		}
		m := c.re.FindStringSubmatch(string(b))
		if m == nil {
			t.Errorf("%s: could not find the remote-support sentence this guard exists to check.\n"+
				"Either the sentence was reworded (update the regex in %s) or it was deleted "+
				"(do not delete it -- it is the statement customers and auditors read). "+
				"Current derived numbers: %d of %d methods unsupported (%d%%).",
				c.path, "remote_support_doc_freshness_test.go", unsupported, total, wantPct)
			continue
		}

		var gotTotal, gotUnsupported int
		if c.totalFirst {
			gotTotal, gotUnsupported = atoi(t, m[1]), atoi(t, m[2])
		} else {
			gotUnsupported, gotTotal = atoi(t, m[1]), atoi(t, m[2])
		}

		if gotTotal != total || gotUnsupported != unsupported {
			t.Errorf("%s is out of date.\n  document says: %d of %d RemoteStorage methods unsupported\n"+
				"  code says:     %d of %d\n%s",
				c.path, gotUnsupported, gotTotal, unsupported, total, updateHint(total, unsupported, wantPct))
		}
		if c.pct {
			if gotPct := atoi(t, m[3]); gotPct != wantPct {
				t.Errorf("%s states %d%% unsupported; derived value is %d%%.\n%s",
					c.path, gotPct, wantPct, updateHint(total, unsupported, wantPct))
			}
		}
	}
}

func updateHint(total, unsupported, pct int) string {
	return fmt.Sprintf(
		"\nUpdate the prose to: %d of %d (%d%%). If a stub was just implemented, also check whether\n"+
			"REMOTE_CLI_SETUP.md's per-area table still describes that area correctly -- the table is\n"+
			"a summary this guard does NOT verify, and it is the part a customer actually reads.",
		unsupported, total, pct)
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("parsing %q from a doc claim: %v", s, err)
	}
	return n
}
