package docsdrift

// gitattributes_union_test.go proves the merge=union lines in .gitattributes
// (CONFLICT-HOTSPOTS-1): for every path declared merge=union, two branches that each
// append one row to the real file merge without conflict and keep both rows. A control
// path without the attribute must conflict, so the test cannot pass vacuously.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// unionLedgers are the append-only, order-insensitive ledgers that must stay on
// merge=union. Dropping one is a deliberate act: remove it here and say why.
var unionLedgers = []string{
	"docs/atomicity-exempt.tsv",
	"docs/besteffort-exempt.tsv",
	"docs/full-row-write-exempt.tsv",
	"docs/child-parent-liveness-exempt.tsv",
	"docs/state-map/class-overrides.tsv",
}

// gitIn runs git in dir with a hermetic identity and no user/system config, and
// returns combined output.
func gitIn(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", append([]string{
		"-c", "user.name=t", "-c", "user.email=t@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
	}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitIn(t, dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// appendRow appends line to the file (adding a newline first if the file lacks one).
func appendRow(t *testing.T, path, line string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	if err := os.WriteFile(path, []byte(s+line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mergeTwoAppends builds a temp repo whose only attributes are attrs, commits base for
// rel, appends rowA on one branch and rowB on another, merges, and returns the merge
// error and the merged file.
func mergeTwoAppends(t *testing.T, attrs, rel string, base []byte, rowA, rowB string) (error, string) {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "init", "-q")
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, base, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte(attrs), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", "-A")
	mustGit(t, dir, "commit", "-q", "-m", "base")
	mustGit(t, dir, "checkout", "-q", "-b", "a")
	appendRow(t, path, rowA)
	mustGit(t, dir, "commit", "-q", "-am", "a")
	mustGit(t, dir, "checkout", "-q", "main")
	mustGit(t, dir, "checkout", "-q", "-b", "b")
	appendRow(t, path, rowB)
	mustGit(t, dir, "commit", "-q", "-am", "b")
	_, err := gitIn(t, dir, "merge", "--no-edit", "a")
	merged, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	return err, string(merged)
}

func TestGitattributesUnionLedgers(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := srcpath.RepoRoot()
	attrs, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}

	declared := map[string]bool{}
	for _, ln := range strings.Split(string(attrs), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		for _, a := range f[1:] {
			if a == "merge=union" {
				declared[f[0]] = true
			}
		}
	}
	for _, p := range unionLedgers {
		if !declared[p] {
			t.Errorf(".gitattributes lacks `%s merge=union`", p)
		}
	}
	for p := range declared {
		found := false
		for _, q := range unionLedgers {
			found = found || p == q
		}
		if !found {
			t.Errorf(".gitattributes declares merge=union for %s: add it to unionLedgers so it is proved", p)
		}
	}

	for _, rel := range unionLedgers {
		t.Run(rel, func(t *testing.T) {
			base, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("ledger missing: %v", err)
			}
			rowA := "UNION-TEST-ROW-A\tx\tfrom branch a"
			rowB := "UNION-TEST-ROW-B\tx\tfrom branch b"
			mergeErr, merged := mergeTwoAppends(t, string(attrs), rel, base, rowA, rowB)
			if mergeErr != nil {
				t.Fatalf("concurrent appends to %s conflicted: %v\n%s", rel, mergeErr, merged[max(0, len(merged)-600):])
			}
			for _, row := range []string{rowA, rowB} {
				if strings.Count(merged, row+"\n") != 1 {
					t.Errorf("merged %s must hold %q exactly once", rel, row)
				}
			}
			if strings.Contains(merged, "<<<<<<<") {
				t.Errorf("merged %s holds conflict markers", rel)
			}
			if !strings.HasPrefix(merged, string(base)) {
				t.Errorf("merged %s changed pre-existing content", rel)
			}
		})
	}

	t.Run("control without the attribute conflicts", func(t *testing.T) {
		mergeErr, _ := mergeTwoAppends(t, "# no merge attributes\n", "docs/plain.tsv", []byte("# header\n"),
			"UNION-TEST-ROW-A\tx", "UNION-TEST-ROW-B\tx")
		if mergeErr == nil {
			t.Fatal("two appends at the same spot merged cleanly without merge=union: the test would pass vacuously")
		}
	})
}
