// cli_remote_check_guard_test.go — a structural guard, in the same family as
// server/http's raw_storage_bypass_guard_test.go, proving every internal/cli
// command file that can reach local/embedded storage
// (common.InitializeCoreService/common.InitializeStorage) also checks remote
// mode (common.NewRemoteClient/common.ResolveRemote) in the same file.
//
// This does NOT prove the check is correct or actually gates the local path
// (a command could call NewRemoteClient and ignore the result) -- that is
// what the behavioral guard (cli_remote_mode_behavior_test.go) is for. This
// guard only proves a check is PRESENT, which is still real signal: its
// entire absence is exactly the class of bug this file was written to catch
// (see docs/opt-in-correctness design note, 2026-09-05) -- ~20 internal/cli
// commands called the local-only initializer with no remote check anywhere
// in the file at all, silently operating on a stray local SQLite file while
// keyorix connect's remote config sat unread.
package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// cliRemoteCheckAllowlist is the exhaustive, reasoned inventory of every
// internal/cli command file that calls common.InitializeCoreService or
// common.InitializeStorage with NO common.NewRemoteClient/common.ResolveRemote
// check anywhere in the same file. Each entry needs a real reason: either the
// command is genuinely local-only by design (and says so to the operator at
// runtime, not just in a doc comment), or it doesn't perform a mutating/
// sensitive operation for which local-vs-remote confusion matters.
//
// Empty for now: every internal/cli command found calling
// InitializeCoreService/InitializeStorage with no remote check anywhere in
// the same file (~25 files, 28 commands, discovered 2026-09-05) turned out to
// be a bug, not a design choice, and has been fixed to either route through
// the real REST API in remote mode or (migrate/user_to_machine.go, which has
// no server-side equivalent) refuse loudly with an actionable message when
// remote mode is configured. Do not add an entry here without the same
// rigor -- fix the command, don't allowlist convenience.
var cliRemoteCheckAllowlist = map[string]string{}

func TestCLICommandsCheckRemoteBeforeLocalStorage(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "cli")
	var flagged []string
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		src := fileHasCall(f, "InitializeCoreService") || fileHasCall(f, "InitializeStorage")
		if !src {
			return nil
		}
		relPath := normalizeCLIPath(path)
		seen[relPath] = true
		if fileHasCall(f, "NewRemoteClient") || fileHasCall(f, "ResolveRemote") {
			return nil
		}
		if _, ok := cliRemoteCheckAllowlist[relPath]; ok {
			return nil
		}
		flagged = append(flagged, relPath)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	sort.Strings(flagged)
	if len(flagged) > 0 {
		t.Errorf("found %d internal/cli file(s) calling InitializeCoreService/InitializeStorage with "+
			"no NewRemoteClient/ResolveRemote check anywhere in the same file: %v -- fetch remote config "+
			"first (see internal/cli/user/create.go for the pattern), or add a reasoned entry to "+
			"cliRemoteCheckAllowlist in this file", len(flagged), flagged)
	}

	var stale []string
	for fn := range cliRemoteCheckAllowlist {
		if !seen[fn] {
			stale = append(stale, fn+" (no longer calls InitializeCoreService/InitializeStorage at all)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("cliRemoteCheckAllowlist entr(y/ies) no longer reproduce: %v\nRemove the entry -- its "+
			"exception no longer applies.", stale)
	}
}

// fileHasCall reports whether f contains any call expression whose selector
// (X.Sel) matches name, regardless of receiver/package qualifier -- this
// deliberately doesn't require the qualifier to be literally "common" so a
// renamed import alias still matches.
func fileHasCall(f *ast.File, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == name {
			found = true
		}
		return true
	})
	return found
}

// normalizeCLIPath converts an absolute or ../-relative walked path into the
// repo-relative form ("internal/cli/...") used as the allowlist key, so the
// guard's own output and the map literal above are directly comparable
// regardless of which directory the test binary happens to run from.
func normalizeCLIPath(path string) string {
	idx := strings.Index(path, "internal/cli/")
	if idx == -1 {
		return path
	}
	return path[idx:]
}
