package refusaldocs

// exit_status_test.go -- BOOT-REFUSAL-TRUTH-NOV-1: the "Exit statuses" table of
// docs/operator/startup-refusals.md against the code.
//
// Two fatal checks, both small on purpose (the general code -> docs direction
// stays log-only, see the package comment):
//
//   - TestExitStatusTableUsesTheServersStatuses: the statuses in the table are
//     exactly the two server/boot_exit.go defines plus 1. A renumbered status
//     (or a fourth one added to the code) makes the page lie to an operator who
//     writes RestartPreventExitStatus= from it.
//   - TestOperatorFixRefusalsAreDocumented: the refusals that were exit 1 and
//     were moved to 78 (EXIT78-1, BOOT-REFUSAL-TRUTH-NOV-1) keep a Match entry on
//     the page. The list is hand-kept: it names the refusals a systemd unit
//     stops on that are not plain configuration errors, and a new one is added
//     here when it is marked. What it does not see: an operatorFix call whose
//     message is not in this list.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var (
	statusConst = regexp.MustCompile(`(?m)^\s*(exitOperatorFix|exitDependencyDown)\s*=\s*(\d+)\s*$`)
	statusRow   = regexp.MustCompile(`^\|\s*(\d+)\s*\|`)
)

// tableStatuses returns the distinct statuses in the first column of the
// "Exit statuses" table, in ascending order.
func tableStatuses(markdown string) []int {
	set := map[int]bool{}
	inSection := false
	for line := range strings.SplitSeq(markdown, "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			inSection = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Exit statuses"
		case inSection:
			if m := statusRow.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				n, _ := strconv.Atoi(m[1])
				set[n] = true
			}
		}
	}
	var out []int
	for n := range set {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func TestExitStatusTableUsesTheServersStatuses(t *testing.T) {
	root := repoRoot(t)
	code, err := os.ReadFile(filepath.Join(root, "server", "boot_exit.go")) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{1: true} // "everything else", documented in boot_exit.go's header
	consts := statusConst.FindAllStringSubmatch(string(code), -1)
	if len(consts) != 2 {
		t.Fatalf("server/boot_exit.go: found %d exit status constants, want exitOperatorFix and exitDependencyDown: the checker needs updating", len(consts))
	}
	for _, c := range consts {
		n, _ := strconv.Atoi(c[2])
		want[n] = true
	}
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docPath))) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	got := tableStatuses(string(doc))
	if len(got) == 0 {
		t.Fatalf("%s: no rows found under \"## Exit statuses\"", docPath)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("%s: the Exit statuses table lists status %d, which server/boot_exit.go does not define", docPath, n)
		}
		delete(want, n)
	}
	for n := range want {
		t.Errorf("%s: the Exit statuses table has no row for status %d, which server/boot_exit.go defines", docPath, n)
	}
}

func TestOperatorFixRefusalsAreDocumented(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docPath))) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	matches := docMatches(string(doc))
	for _, need := range []string{
		"KEYORIX_BOOTSTRAP_TOKEN too short",                    // server/bootstrap_token.go, exit 78
		"PostgreSQL session_replication_role is",               // storage.NonOriginReplicationRoleError, exit 78 (server and admin)
		"existing row group(s) normalize to the same identity", // storage.FoldCollisionError (78 for projects only), text shared by all tables
	} {
		found := false
		for _, m := range matches {
			if strings.Contains(m, need) || strings.Contains(need, m) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s has no Match entry for %q, a refusal the server exits 78 for", docPath, need)
		}
	}
}

func TestTableStatusesParsing(t *testing.T) {
	md := "| 78 | before the section |\n\n## Exit statuses\n\n| Exit | What |\n|---|---|\n| 78 | a |\n| 75 | b |\n| 78 | c |\n| 1 | d |\n\n## Next\n\n| 2 | after |\n"
	got := tableStatuses(md)
	if len(got) != 3 || got[0] != 1 || got[1] != 75 || got[2] != 78 {
		t.Fatalf("tableStatuses = %v, want [1 75 78]", got)
	}
}
