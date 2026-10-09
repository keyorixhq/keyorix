package faultops

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// opCatalogOrderGolden is the index→Key list of opCatalog, one key per line,
// line N = index N-1.
const opCatalogOrderGolden = "testdata/opcatalog-order.golden"

// TestOpCatalogOrder_PinnedPrefix pins opCatalog's order until the corpus is
// re-encoded as v2 (seed_v2_test.go). A legacy seed addresses its op as
// `data[0] % len(opCatalog)`, so reordering, removing or inserting an op
// anywhere before the end silently re-points committed seeds — they keep
// passing while testing a different operation (#2396's SAML op shifted the
// WebAuthn ops). This turns that into a loud, named failure.
//
// It checks a PREFIX: every golden line must still be at the same index.
// Appending ops at the end (new ops_<area>_test.go registrations, or an
// init()-time append in a file that sorts last) passes without touching the
// golden file, so op-adding PRs do not all conflict on it.
//
// What it does NOT catch: a seed whose data[0] is >= len(opCatalog) is
// re-pointed by ANY growth, appends included (data[0] % len changes) — only
// v2 addressing fixes that. Nor does it cover the faulted-method dimension
// (storage.Storage's reflect order is alphabetical and shifts on most storage
// PRs); see TestReportSeedIntentDrift.
//
// To extend the pin after appends (optional, in a quiet window):
// OPCATALOG_GOLDEN_UPDATE=1 go test ./server/faultops/ -run TestOpCatalogOrder_PinnedPrefix
func TestOpCatalogOrder_PinnedPrefix(t *testing.T) {
	if os.Getenv("OPCATALOG_GOLDEN_UPDATE") == "1" {
		var b strings.Builder
		for _, op := range opCatalog {
			b.WriteString(op.Key)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(opCatalogOrderGolden, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d keys to %s", len(opCatalog), opCatalogOrderGolden)
		return
	}
	raw, err := os.ReadFile(opCatalogOrderGolden)
	if err != nil {
		t.Fatalf("reading %s: %v", opCatalogOrderGolden, err)
	}
	golden := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(golden) == 0 || golden[0] == "" {
		t.Fatalf("%s is empty — a pin with no entries cannot fail", opCatalogOrderGolden)
	}
	if len(opCatalog) < len(golden) {
		t.Fatalf("opCatalog has %d ops but %s pins %d — an op was REMOVED, which re-points every committed legacy "+
			"seed whose index is after it. Re-encode the corpus as v2 first (go run scripts/fuzzing/reencode-seeds.go), "+
			"then regenerate the pin (OPCATALOG_GOLDEN_UPDATE=1).", len(opCatalog), opCatalogOrderGolden, len(golden))
	}
	var moved []string
	for i, want := range golden {
		if got := opCatalog[i].Key; got != want {
			moved = append(moved, "  index "+strconv.Itoa(i)+": pinned "+want+", now "+got)
		}
	}
	if len(moved) > 0 {
		if len(moved) > 10 {
			moved = append(moved[:10], "  ...")
		}
		t.Fatalf("opCatalog was REORDERED (or an op inserted/removed before the end): committed legacy fuzz seeds "+
			"address ops by index, so they now silently replay a DIFFERENT operation and still pass. New ops must be "+
			"appended (register them from ops_<area>_test.go, or append from an init() in a file that sorts after every "+
			"other op file). If the reorder is intended: re-encode the corpus as v2 first "+
			"(go run scripts/fuzzing/reencode-seeds.go), then regenerate the pin (OPCATALOG_GOLDEN_UPDATE=1).\n%s",
			strings.Join(moved, "\n"))
	}
}
