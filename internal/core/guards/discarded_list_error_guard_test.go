// discarded_list_error_guard_test.go -- ERRLOSS-TAILS-1 item 3.
//
// The class: `pats, _ := tx.ListPersonalAccessTokensByUser(...)`. A storage read whose error is
// thrown away yields an empty value on failure, and when that value feeds a revocation or an
// authorization decision the failure silently becomes "nothing to revoke" / "nothing to check".
// ERRLOSS-REVOKE-1 (#3777) fixed the session-hash listings; this item found the PAT listing in
// setAccountStateInTx the same way. The guard sweeps the core family for the shape so the next
// one is a red test instead of a review finding.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - an assignment or `var` declaration with at least two left-hand sides, whose LAST left-hand
//     side is the blank identifier and whose FIRST is not (so the value is kept, the error is
//     dropped), whose right-hand side is ONE call of a method named List*, Get*, Find*, Count*,
//     Resolve* or Lookup*, on a receiver that looks like the storage layer (an identifier tx, sp,
//     s, st, store, storage, txn or savepoint; a selector ending .storage, .store or .Storage;
//     or a call to .Storage());
//   - inside a function whose NAME, or whose file's NAME, contains a revocation or authorization
//     word (decisionWords below).
//
// What it does NOT catch:
//   - data flow: it does not check that the kept value really reaches a decision. The function
//     and file name stand in for that, so a decision made in a helper with a neutral name in a
//     neutral file is invisible (the word list had to learn "account state" because the very
//     function this guard was written for, setAccountStateInTx in account_state.go, names no
//     revocation word), and a hit in a revocation-named function that only logs is a false
//     positive (put it in an exception file with the reason);
//   - other ways to lose the error: `x, err := ...; _ = err`, an error assigned and never read,
//     `x, _ = a.b.List...()` through an unrecognised receiver name, a call made through a stored
//     func value or an interface-typed helper, a discard in a go/defer statement;
//   - `_, _ = ...` and `_ = ...` (nothing kept, so no value feeds a decision);
//   - methods outside the prefix list above (a `Load*`, `Fetch*`, `Has*`);
//   - code outside the core family (srcpath.CoreFamilyGoFiles): the server layers, the CLI.
// Wrong-reason exemptions are checked too: an exception that no longer matches any hit fails.
//
// Report-only on its first day (docs/guard-rollout.d/TestNoDiscardedStorageReadErrorOnDecisionPath.tsv,
// docs/guard-rollout-contract.md).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// decisionWords: a function or file whose name contains one of these makes a decision about
// who may do what, or about taking access away.
var decisionWords = regexp.MustCompile(`(?i)(revo|suspend|deactivat|deprovision|evict|account.?state|block|restrict|lockout|disable|authori[sz]|permission|ceiling|grant|access|auth|role|share|session|token|membership|acl|ownership|guard|require|forbid|deny|allow)`)

var storageReadPrefixes = []string{"List", "Get", "Find", "Count", "Resolve", "Lookup"}

var storageReceiverIdents = map[string]bool{"tx": true, "sp": true, "s": true, "st": true, "store": true, "storage": true, "txn": true, "savepoint": true}

// discardedReadExceptions: "file.go:FuncName" -> why the discarded error is safe. Filled one
// file per row by registerDiscardedReadException from discarded_list_error_exception_*_test.go.
var discardedReadExceptions = map[string]string{}

func registerDiscardedReadException(key, reason string) {
	if _, dup := discardedReadExceptions[key]; dup {
		panic("duplicate discarded-read exception " + key)
	}
	discardedReadExceptions[key] = reason
}

type discardedRead struct {
	File, Func, Callee string
	Line               int
	InDecision         bool
}

func (d discardedRead) key() string { return d.File + ":" + d.Func }

// scanDiscardedReads returns every recognised discard in src (file name file).
func scanDiscardedReads(fset *token.FileSet, f *ast.File, file string) []discardedRead {
	var out []discardedRead
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		inDecision := decisionWords.MatchString(fn.Name.Name) || decisionWords.MatchString(strings.TrimSuffix(file, ".go"))
		check := func(lhs []ast.Expr, rhs []ast.Expr, pos token.Pos) {
			if len(lhs) < 2 || len(rhs) != 1 || !isBlank(lhs[len(lhs)-1]) || isBlank(lhs[0]) {
				return
			}
			call, ok := rhs[0].(*ast.CallExpr)
			if !ok {
				return
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !hasReadPrefix(sel.Sel.Name) || !looksLikeStorage(sel.X) {
				return
			}
			out = append(out, discardedRead{File: file, Func: fn.Name.Name, Callee: sel.Sel.Name, Line: fset.Position(pos).Line, InDecision: inDecision})
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				check(s.Lhs, s.Rhs, s.Pos())
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, len(s.Names))
				for i, nm := range s.Names {
					lhs[i] = nm
				}
				check(lhs, s.Values, s.Pos())
			}
			return true
		})
	}
	return out
}

func isBlank(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "_"
}

func hasReadPrefix(name string) bool {
	for _, p := range storageReadPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func looksLikeStorage(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return storageReceiverIdents[x.Name]
	case *ast.SelectorExpr:
		return x.Sel.Name == "storage" || x.Sel.Name == "store" || x.Sel.Name == "Storage"
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Storage"
	}
	return false
}

func scanDiscardedReadsInSource(t testing.TB, file, src string) []discardedRead {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanDiscardedReads(fset, f, filepath.Base(file))
}

// The planted shapes. Each must be found (red) and the safe ones must not be (green): "a guard
// nobody has watched fail is not a guard", and one that always fails is as useless.
func TestDiscardedReadScanner_Calibration(t *testing.T) {
	hit := func(src string) []discardedRead { return scanDiscardedReadsInSource(t, "account_state.go", src) }
	wantInDecision := func(name, src string) {
		t.Helper()
		got := hit(src)
		if len(got) != 1 || !got[0].InDecision {
			t.Errorf("%s: want exactly one decision-path hit, got %+v", name, got)
		}
	}
	// The exact line origin/main had in setAccountStateInTx.
	wantInDecision("if-init discard", `package core
func (c *K) setAccountStateInTx() {
	if pats, _ := tx.ListPersonalAccessTokensByUser(ctx, userID); len(pats) > 0 {
		_ = pats
	}
}`)
	wantInDecision("assign through c.storage", `package core
func (c *K) revokeThings() {
	hashes, _ = c.storage.ListSessionTokenHashesForUser(ctx, id)
}`)
	wantInDecision("var declaration", `package core
func (c *K) suspendX() {
	var grants, _ = c.Storage().GetUserRoleIDsAt(ctx, id, sc)
	_ = grants
}`)
	wantInDecision("savepoint receiver", `package core
func evictUser() {
	rows, _ := sp.FindSessions(ctx, id)
	_ = rows
}`)

	for name, src := range map[string]string{
		"error handled":      "package core\nfunc revoke() {\n\tpats, err := tx.ListPersonalAccessTokensByUser(ctx, id)\n\t_, _ = pats, err\n}",
		"nothing kept":       "package core\nfunc revoke() {\n\t_, _ = tx.ListPersonalAccessTokensByUser(ctx, id)\n}",
		"not a storage recv": "package core\nfunc revoke() {\n\tpats, _ := strs.ListThings(id)\n\t_ = pats\n}",
		"not a read prefix":  "package core\nfunc revoke() {\n\tpats, _ := tx.DeleteThings(id)\n\t_ = pats\n}",
		"single value":       "package core\nfunc revoke() {\n\tn := tx.ListCount(id)\n\t_ = n\n}",
	} {
		if got := hit(src); len(got) != 0 {
			t.Errorf("%s: want no hit, got %+v", name, got)
		}
	}

	// A neutral function in a neutral file is a candidate but not a decision path.
	got := scanDiscardedReadsInSource(t, "dashboard.go", "package core\nfunc snapshot() {\n\tx, _ := c.storage.GetPreviousStatsSnapshot(ctx, id)\n\t_ = x\n}")
	if len(got) != 1 || got[0].InDecision {
		t.Errorf("neutral function: want one non-decision candidate, got %+v", got)
	}
}

func TestNoDiscardedStorageReadErrorOnDecisionPath(t *testing.T) {
	g := guardrules.Rollout(t)
	var all, hits []discardedRead
	for _, path := range coreFamilySources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel := srcpath.CoreFamilyRel(path)
		for _, d := range scanDiscardedReads(fset, f, rel) {
			all = append(all, d)
			if d.InDecision {
				hits = append(hits, d)
			}
		}
	}
	// A floor on the candidates, so a matcher that silently matches nothing fails loudly
	// instead of leaving a green guard (3 today: the authz group-membership read, the stats
	// snapshot, the impersonation action count).
	if len(all) < 3 {
		t.Fatalf("scanner found only %d discarded storage reads in the whole core family; it has stopped matching", len(all))
	}

	used := map[string]bool{}
	var msgs []string
	for _, d := range hits {
		if _, ok := discardedReadExceptions[d.key()]; ok {
			used[d.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s discards the error of %s and keeps its value", d.File, d.Line, d.Func, d.Callee))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: a failed read yields an empty value that a revocation/authorization decision then trusts. "+
			"Handle the error (savepoint + one retry inside a transaction, then fail or fail closed), or add a "+
			"discarded_list_error_exception_<name>_test.go calling registerDiscardedReadException with the reason it is safe", m)
	}
	for key, why := range discardedReadExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its file", key, why)
		}
	}
}
