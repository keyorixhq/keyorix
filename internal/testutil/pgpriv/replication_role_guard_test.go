package pgpriv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// setReplicationRole matches a SQL string that changes session_replication_role
// for a session: "SET [LOCAL|SESSION] session_replication_role" and the
// "ALTER DATABASE|ROLE ... SET session_replication_role" forms. RESET, a
// SHOW, a Helm --set key ("settings.session_replication_role=replica") and
// comments do not match.
var setReplicationRole = regexp.MustCompile(`(?i)\bSET\s+(?:(?:LOCAL|SESSION)\s+)?session_replication_role\b`)

// TestEveryReplicationRoleTestRequiresThePrivilege fails when a *_test.go file
// holds a SQL string that sets session_replication_role without calling
// pgpriv.RequireReplicationRolePrivilege. Without the call such a test is red
// on any role that is not a superuser (the sandbox kpg role) and a hand-written
// skip is invisible in CI; the helper skips locally and fails under CI=true.
//
// What it checks: every *_test.go of the root module (nested modules are
// skipped, as are testdata, vendor and node_modules), parsed with go/parser;
// the string literals of the file are matched with setReplicationRole.
//
// What it does NOT check: that the call comes before the SET or in the same
// function (the unit is the file); a statement assembled from several literals
// ("SET " + "session_replication_role"); a server-side setting reached by
// other means (a DSN startup parameter, PGOPTIONS). ALTER ... DISABLE TRIGGER
// is not matched either: it needs table ownership, not this privilege, and the
// tests that use it run on kpg.
func TestEveryReplicationRoleTestRequiresThePrivilege(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".scratch", "vendor", "testdata":
				return filepath.SkipDir
			}
			if path != root {
				if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
					return filepath.SkipDir // nested module, scanned by its own go test
				}
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, "_test.go") || rel == "internal/testutil/pgpriv/replication_role_guard_test.go" {
			return nil
		}
		src, readErr := os.ReadFile(path) // #nosec G304 -- walks the repository
		if readErr != nil {
			g.Errorf("read %s: %v", rel, readErr)
			return nil
		}
		lines, parseErr := replicationRoleWithoutHelper(rel, src)
		if parseErr != nil {
			g.Errorf("parse %s: %v", rel, parseErr)
			return nil
		}
		for _, line := range lines {
			g.Errorf("%s:%d sets session_replication_role but the file never calls pgpriv.RequireReplicationRolePrivilege; "+
				"add the call to the test (internal/testutil/pgpriv)", rel, line)
		}
		return nil
	})
	if err != nil {
		g.Fatal(err)
	}
}

// TestReplicationRoleGuard_FixturesRedGreen calibrates the matcher on two
// fixture files: one that sets the role without the call (must be flagged),
// one that calls the helper (must pass), and a third that only mentions the
// setting (comment, RESET, Helm key) and must not be flagged either.
func TestReplicationRoleGuard_FixturesRedGreen(t *testing.T) {
	cases := []struct {
		file string
		want int
	}{
		{"missing_helper.go.txt", 2},
		{"with_helper.go.txt", 0},
		{"mentions_only.go.txt", 0},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", "replication_role_guard", c.file))
			if err != nil {
				t.Fatal(err)
			}
			lines, err := replicationRoleWithoutHelper(c.file, src)
			if err != nil {
				t.Fatal(err)
			}
			if len(lines) != c.want {
				t.Fatalf("%s: flagged lines %v, want %d", c.file, lines, c.want)
			}
		})
	}
}

// replicationRoleWithoutHelper returns the line of every SQL string in src that
// sets session_replication_role, or nil when src calls
// pgpriv.RequireReplicationRolePrivilege.
func replicationRoleWithoutHelper(name string, src []byte) ([]int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var sets []int
	calls := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			if s, uerr := strconv.Unquote(x.Value); uerr == nil && setReplicationRole.MatchString(s) {
				sets = append(sets, fset.Position(x.Pos()).Line)
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RequireReplicationRolePrivilege" {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "pgpriv" {
					calls = true
				}
			}
		}
		return true
	})
	if calls {
		return nil, nil
	}
	return sets, nil
}
