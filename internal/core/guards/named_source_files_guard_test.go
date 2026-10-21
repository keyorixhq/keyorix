package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// R6 of ADR-116 (INV-CORE-package-boundaries): a guard that names a source file
// by a string literal ("secrets.go", "internal/core/sso.go", or the file part of a
// "secrets.go:Func" allowlist key) goes vacuous when that file moves: the scan
// that looked for it finds nothing and the allowlist row it keys no longer
// matches anything. TestNamedSourceFilesExist makes the move red instead.
//
// Scanned: every _test.go file under namedFileScanRoots. Skipped: suffix
// patterns ("_test.go", ".gen.go") and every literal inside a function that
// calls t.TempDir() (or (*testing.B/F).TempDir): those name synthetic fixture
// files, not repository files. A literal is resolved,
// in order, as a path relative to the repository root, relative to the test
// file's directory, and (bare names only) as a file in the test file's own
// directory, in a core family directory (srcpath.CoreFamilyDirs) or in
// namedFileSearchDirs. A literal that resolves nowhere must be on
// namedFileAllowlist with the reason it is intentionally absent.
//
// What this does not check: names assembled at run time (filepath.Join of
// parts, Sprintf), names inside comments, and which of several same-named
// files a bare name meant.

var namedFileScanRoots = []string{"internal/core", "server/http", "internal/statemap"}

// namedFileSearchDirs: where bare names are looked up besides the test file's
// own directory and the core family. Beyond the handler dirs these are the
// packages core guards name by file (storage implementations, the generated
// fault wrapper, rotation backends).
var namedFileSearchDirs = []string{
	"server/http", "server/http/handlers",
	"internal/core/storage", "internal/storage/store", "internal/faultstorage", "internal/rotation", "server/proto/pb",
}

// namedFileAllowlist: "<test file>:<literal>" -> why the named file does not
// exist. Today every entry is a synthetic, in-memory fixture name of a
// self-test (a source string parsed under a made-up file name).
var namedFileAllowlist = map[string]string{
	"internal/core/guards/account_state_exhaustiveness_guard_test.go:account_state_fixture.go": synthetic,
	"internal/core/guards/csv_writer_completeness_test.go:csv_fixture.go":                      synthetic,
	"internal/core/guards/notify_recipients_guard_test.go:good.go":                             synthetic,
	"internal/core/guards/notify_recipients_guard_test.go:liar.go":                             synthetic,
	"internal/core/guards/notify_recipients_guard_test.go:planted.go":                          synthetic,
	"internal/core/guards/package_stays_light_guard_test.go:embeds_bare.go":                    synthetic,
	"internal/core/guards/package_stays_light_guard_test.go:embeds_pkg.go":                     synthetic,
	"internal/core/guards/package_stays_light_guard_test.go:embeds_ptr.go":                     synthetic,
	"internal/core/guards/package_stays_light_guard_test.go:imports_core.go":                   synthetic,
	"internal/core/guards/package_stays_light_guard_test.go:named_field.go":                    synthetic,
	"internal/core/guards/package_stays_light_guard_test.go:subpackage.go":                     synthetic,
	"internal/core/guards/role_read_wrapper_forwarding_guard_test.go:a/x.go":                   synthetic,
	"internal/core/guards/role_read_wrapper_forwarding_guard_test.go:a/y.go":                   synthetic,
	"internal/core/guards/role_read_wrapper_forwarding_guard_test.go:b/y.go":                   synthetic,
	"internal/core/guards/session_auth_read_wrapper_forwarding_guard_test.go:a/x.go":           synthetic,
	"internal/core/guards/session_auth_read_wrapper_forwarding_guard_test.go:a/y.go":           synthetic,
	"internal/core/guards/session_auth_read_wrapper_forwarding_guard_test.go:b/y.go":           synthetic,
	"internal/core/guards/tx_closure_outer_storage_guard_test.go:planted.go":                   synthetic,
	"internal/core/hook_storage_selftest_test.go:x_test.go":                                    synthetic,
	"internal/core/hook_storage_selftest_test.go:y_test.go":                                    synthetic,
	"internal/statemap/no_time_local_assignment_guard_test.go:x_test.go":                       synthetic,
	"internal/statemap/rest_composition_test.go:fixture.go":                                    synthetic,
	"internal/statemap/test_tempdir_cleanup_guard_test.go:x_test.go":                           synthetic,
	"server/http/full_row_overwrite_guard_test.go:overwrite_fixture.go":                        synthetic,
	"server/http/secret_acl_gate_guard_test.go:server/http/handlers/zz_third.go":               synthetic,
	"server/http/secret_acl_gate_guard_test.go:x.go":                                           synthetic,
	"server/http/share_secret_isgroup_guard_test.go:x.go":                                      synthetic,
}

const synthetic = "synthetic fixture name in a self-test"

// namedFileLiteralRe matches a literal that is a .go file name or path, optionally
// followed by ":<symbol>" (allowlist keys such as "secrets.go:CreateSecret").
var namedFileLiteralRe = regexp.MustCompile(`^([A-Za-z0-9_./-]+\.go)(:[A-Za-z0-9_.()*:-]+)?$`)

type namedFileRef struct {
	testFile string // repository-relative, slash-separated
	name     string // the .go part of the literal
}

func (r namedFileRef) key() string { return r.testFile + ":" + r.name }

// namedFileRefs returns every .go-file literal in the _test.go files under roots.
func namedFileRefs(repo string, roots []string) ([]namedFileRef, error) {
	var refs []namedFileRef
	fset := token.NewFileSet()
	for _, r := range roots {
		err := filepath.WalkDir(filepath.Join(repo, filepath.FromSlash(r)), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repo, path)
			rel = filepath.ToSlash(rel)
			seen := map[string]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if fd, ok := n.(*ast.FuncDecl); ok && fd.Body != nil && callsTempDir(fd.Body) {
					return false // synthetic fixture names
				}
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if m := namedFileLiteralRe.FindStringSubmatch(v); m != nil && !seen[m[1]] && !strings.HasPrefix(filepath.Base(m[1]), "_") &&
					!strings.HasPrefix(filepath.Base(m[1]), ".") {
					seen[m[1]] = true
					refs = append(refs, namedFileRef{testFile: rel, name: m[1]})
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func callsTempDir(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "TempDir" {
				found = true
			}
		}
		return !found
	})
	return found
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// resolveNamedFile reports whether ref names an existing file (rules above).
func resolveNamedFile(repo string, ref namedFileRef, searchDirs []string) bool {
	name := filepath.FromSlash(ref.name)
	testDir := filepath.Dir(filepath.Join(repo, filepath.FromSlash(ref.testFile)))
	if fileExists(filepath.Join(repo, name)) || fileExists(filepath.Join(testDir, name)) {
		return true
	}
	if strings.Contains(ref.name, "/") {
		return false
	}
	for _, d := range searchDirs {
		if fileExists(filepath.Join(d, name)) {
			return true
		}
	}
	return false
}

func namedFileViolations(repo string, refs []namedFileRef, searchDirs []string, allow map[string]string) []string {
	var msgs []string
	used := map[string]bool{}
	for _, ref := range refs {
		if resolveNamedFile(repo, ref, searchDirs) {
			continue
		}
		if _, ok := allow[ref.key()]; ok {
			used[ref.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s names %q, which does not exist (moved or renamed?). Point the guard at the "+
			"file's new place, or add %q to namedFileAllowlist with the reason it is intentionally absent (ADR-116 R6)",
			ref.testFile, ref.name, ref.key()))
	}
	for _, k := range slices.Sorted(maps.Keys(allow)) {
		if !used[k] {
			msgs = append(msgs, fmt.Sprintf("namedFileAllowlist entry %s is not needed (the literal is gone or the file exists): remove it", k))
		}
	}
	slices.Sort(msgs)
	return msgs
}

func namedFileSearchPath(repo string) []string {
	dirs := slices.Clone(srcpath.CoreFamilyDirs())
	for _, d := range namedFileSearchDirs {
		dirs = append(dirs, filepath.Join(repo, filepath.FromSlash(d)))
	}
	return dirs
}

func TestNamedSourceFilesExist(t *testing.T) {
	t.Parallel()
	repo := srcpath.RepoRoot()
	refs, err := namedFileRefs(repo, namedFileScanRoots)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) < 50 {
		t.Fatalf("found only %d file-name literals: the scan is broken", len(refs))
	}
	t.Logf("%d file-name literals in %v checked", len(refs), namedFileScanRoots)
	for _, msg := range namedFileViolations(repo, refs, namedFileSearchPath(repo), namedFileAllowlist) {
		t.Error(msg)
	}
	for k, why := range namedFileAllowlist {
		if strings.TrimSpace(why) == "" {
			t.Errorf("namedFileAllowlist entry %s has no reason", k)
		}
	}
}

func TestNamedFileViolations_SelfTest(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	writeTree(t, repo, map[string]string{
		"internal/core/secrets.go":       "package core\n",
		"internal/core/storage/iface.go": "package storage\n",
		"internal/core/guards/g_test.go": "package guards\n" +
			"var keys = []string{\"secrets.go:CreateSecret\", \"internal/core/storage/iface.go\", \"../secrets.go\", \"_test.go\"}\n" +
			"var stale = \"moved_away.go:Fn\"\n" +
			"func TestFixture(t *testing.T) { dir := t.TempDir(); _ = dir + \"made_up.go\" }\n",
	})
	refs, err := namedFileRefs(repo, []string{"internal/core"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 4 {
		t.Fatalf("want 4 refs (suffix pattern and TempDir fixture skipped), got %v", refs)
	}
	search := []string{filepath.Join(repo, "internal", "core")}
	msgs := namedFileViolations(repo, refs, search, nil)
	if len(msgs) != 1 || !strings.Contains(msgs[0], `names "moved_away.go"`) {
		t.Fatalf("only the stale name must be red: %v", msgs)
	}
	allow := map[string]string{"internal/core/guards/g_test.go:moved_away.go": "x", "internal/core/guards/g_test.go:gone.go": "y"}
	msgs = namedFileViolations(repo, refs, search, allow)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "g_test.go:gone.go is not needed") {
		t.Fatalf("an allowlisted name is green and an unused entry is red: %v", msgs)
	}
}
