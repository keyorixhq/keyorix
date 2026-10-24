package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestLockLossKind_EveryHolderIsNamed: every who a lock holder passes maps to
// its own lock label, not other. The literal whos are found in the source
// (calls of WatchPinnedLockConn, WatchPinnedLockConnGated,
// ReportAdvisoryLockLost and advisoryLockSession.watch whose who argument is a
// string literal); a who passed as a constant or built at run time is not
// found by the scan, so those are listed by hand below.
func TestLockLossKind_EveryHolderIsNamed(t *testing.T) {
	re := regexp.MustCompile(`(?:WatchPinnedLockConn(?:Gated)?\([^,()]+,\s*(?:[^,()]+,\s*)?|ReportAdvisoryLockLost\(|\.watch\(\w+,\s*)"([^"]+)"`)
	var found []string
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "server"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path) // #nosec G304 -- test reads this repository's own source
			if err != nil {
				return err
			}
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				found = append(found, m[1])
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) < 7 {
		t.Fatalf("the source scan found only %d lock holders (%q): the call shapes it recognises have changed", len(found), found)
	}
	// Passed as a constant (serverguard.keyInitLockWho) or built at run time
	// ("named lock "+key).
	found = append(found, "key-initialisation lock", "named lock some-key")
	for _, who := range found {
		if lockLossKind(who) == "other" {
			t.Errorf("lock holder %q has no lock label: add its prefix to lockLossKinds (and to the metric help)", who)
		}
	}
}

func TestReportAdvisoryLockLost_CountsByLock(t *testing.T) {
	before := testutil.ToFloat64(advisoryLockLost.WithLabelValues("scheduler"))
	ReportAdvisoryLockLost("scheduler lock", errors.New("driver: bad connection"))
	if got := testutil.ToFloat64(advisoryLockLost.WithLabelValues("scheduler")) - before; got != 1 {
		t.Fatalf("keyorix_advisory_lock_lost_total{lock=scheduler} rose by %v, want 1", got)
	}
	if got := lockLossKind("something new"); got != "other" {
		t.Fatalf("lockLossKind(unknown) = %q, want other", got)
	}
}
