package store

// full_row_safe_cas_writers_guard_test.go — STORE-STATE-WRITERS-NOV-1.
//
// A SAFE-CAS row of docs/full-row-write-exempt.tsv exempts a full-row writer on two
// grounds: its conditional WHERE stops a stale struct once a concurrent writer has
// moved the row on, and no OTHER writer of the table changes a column that the stale
// struct would write back. The interleave tests (full_row_writer_*interleave_test.go)
// check the first ground against the writers that exist today. The second ground is a
// claim about every other writer of the table, and nothing checked it: a new
// Updates(map) on machine_identities would have voided the verdict with every test
// still green.
//
// This guard derives the SAFE-CAS models from the ledger and their tables from the
// GORM schema. It then sweeps this package's production files for every
// update-shaped write of one of those tables. Each write that is not the ledgered
// writer itself must carry a marker on the call's line or in the comment right
// above it:
//
//	// safe-cas-writer-ok: <Model>: <why the SAFE-CAS writer of Model cannot revert it>
//
// The marker goes with the new writer (docs/guard-rollout-contract.md rule 3), so the
// PR that adds a writer also re-reviews the ledger row. A marker that matches no
// write fails too, so markers cannot outlive their write.
//
// Write shapes recognised: Update, Updates, UpdateColumn, UpdateColumns and Save. The
// table can come from the receiver chain through Model(&models.X{}),
// Model(new(models.X)), Model(<typed variable>) or Table("<name>"), including a chain
// that starts from a local variable (q := tx.Model(...); q.Update(...)). Failing that,
// it comes from a models.X argument of Updates/UpdateColumns/Save. Exec of a string
// literal is matched on "UPDATE <table>". An update-shaped gorm call whose table cannot
// be resolved fails the guard (fail closed).
//
// What it does NOT check: writers outside internal/storage/store (core writes through
// storage, and the migrations in internal/storage run before the server takes
// requests), deletes and creates (neither writes a stale column back, and a CAS on a
// deleted row matches nothing), and whether a marker's reason is true. Judging the
// reason is the reviewer's job, as it is for the ledger row.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const safeCASWriterMarker = "safe-cas-writer-ok:"

// safeCASMinReason is the shortest marker justification accepted after the model.
const safeCASMinReason = 20

// safeCASUpdateCalls are the gorm methods that change columns of existing rows.
var safeCASUpdateCalls = map[string]bool{
	"Update": true, "Updates": true, "UpdateColumn": true, "UpdateColumns": true, "Save": true,
}

// safeCASGormChain are receiver-chain methods that mark a call as a gorm call.
var safeCASGormChain = map[string]bool{
	"Model": true, "Table": true, "Where": true, "WithContext": true, "Select": true,
	"Omit": true, "Clauses": true, "Session": true, "Unscoped": true, "Not": true, "Or": true,
}

var safeCASExecUpdateRe = regexp.MustCompile(`(?i)\bUPDATE\s+"?([a-z_][a-z0-9_]*)"?`)

// safeCASLedger is what the sweep needs from the ledger: per SAFE-CAS model, the
// file<TAB>function keys of its ledgered writers.
type safeCASLedger map[string]map[string]bool

func loadSafeCASLedger(t *testing.T) safeCASLedger {
	t.Helper()
	out := safeCASLedger{}
	for _, r := range loadFullRowExempt(t) {
		if isFullRowCallerRow(r) || !strings.HasPrefix(r.Reason, "SAFE-CAS") {
			continue
		}
		if out[r.Model] == nil {
			out[r.Model] = map[string]bool{}
		}
		out[r.Model][r.File+"\t"+r.Func] = true
	}
	return out
}

// modelTables maps every model's table name to its model name, and back.
func modelTables(t testing.TB) (tableToModel, modelToTable map[string]string) {
	t.Helper()
	tableToModel, modelToTable = map[string]string{}, map[string]string{}
	cache := &sync.Map{}
	for _, m := range models.AllTestModels() {
		s, err := schema.Parse(m, cache, schema.NamingStrategy{})
		require.NoError(t, err)
		tt := reflect.TypeOf(m)
		for tt.Kind() == reflect.Pointer {
			tt = tt.Elem()
		}
		tableToModel[s.Table] = tt.Name()
		modelToTable[tt.Name()] = s.Table
	}
	return tableToModel, modelToTable
}

type safeCASMarker struct {
	file      string
	line      int
	model     string
	reason    string
	endOfNote int // last line of the comment group holding the marker
	used      bool
}

// safeCASScan sweeps dir's non-test .go files (flat) and returns one finding per
// unmarked write, unresolved write, malformed marker and unused marker.
func safeCASScan(t testing.TB, dir string, rel func(string) string, cas safeCASLedger, tableToModel map[string]string) []string {
	t.Helper()
	var findings []string
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var markers []*safeCASMarker
	type parsed struct {
		path string
		fset *token.FileSet
		f    *ast.File
	}
	var files []parsed
	helpers := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		require.NoError(t, perr)
		files = append(files, parsed{path, fset, f})
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && returnsGormDB(fd) {
				helpers[fd.Name.Name] = fd
			}
		}
	}
	for _, pf := range files {
		path, fset, f := pf.path, pf.fset, pf.f
		file := rel(path)
		var fileMarkers []*safeCASMarker
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				_, after, ok := strings.Cut(c.Text, safeCASWriterMarker)
				if !ok {
					continue
				}
				line := fset.Position(c.Pos()).Line
				model, reason, _ := strings.Cut(strings.TrimSpace(after), ":")
				model, reason = strings.TrimSpace(model), strings.TrimSpace(reason)
				if cas[model] == nil || len(reason) < safeCASMinReason {
					findings = append(findings, fmt.Sprintf("%s:%d malformed marker: want %q followed by a SAFE-CAS model, a colon and a reason of at least %d characters", file, line, safeCASWriterMarker, safeCASMinReason))
					continue
				}
				fileMarkers = append(fileMarkers, &safeCASMarker{file: file, line: line, model: model, reason: reason, endOfNote: fset.Position(cg.End()).Line})
			}
		}
		markers = append(markers, fileMarkers...)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := funcDisplayName(fd)
			env := newTypeEnv(fd)
			assigned := map[string][]ast.Expr{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				env.observe(n)
				if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
					for i, l := range as.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							assigned[id.Name] = append(assigned[id.Name], as.Rhs[i])
						}
					}
				}
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				var model string
				switch {
				case sel.Sel.Name == "Exec" && len(ce.Args) >= 1:
					sql, isLit := stringLiteral(ce.Args[0])
					if !isLit {
						return true // a non-literal Exec: see the doc comment
					}
					m := safeCASExecUpdateRe.FindStringSubmatch(sql)
					if m == nil {
						return true
					}
					model = tableToModel[m[1]]
				case safeCASUpdateCalls[sel.Sel.Name]:
					ch := (&safeCASResolver{env: env, assigned: assigned, tableToModel: tableToModel, helpers: helpers}).chain(sel.X, 0)
					model = ch.model
					if model == "" && ch.table == "" && (sel.Sel.Name == "Updates" || sel.Sel.Name == "UpdateColumns" || sel.Sel.Name == "Save") && len(ce.Args) == 1 {
						model = env.modelOf(ce.Args[0])
					}
					if model == "" && ch.table == "" {
						if !ch.gorm {
							return true // not a gorm call (no chain method, no db handle)
						}
						findings = append(findings, fmt.Sprintf("%s:%d %s %s: cannot tell which table this write updates; name it with Model(&models.X{}) or Table(\"x\") in the chain", file, fset.Position(ce.Pos()).Line, fn, sel.Sel.Name))
						return true
					}
				default:
					return true
				}
				if model == "" || cas[model] == nil {
					return true
				}
				if cas[model][file+"\t"+fn] {
					return true // the ledgered SAFE-CAS writer itself
				}
				start, end := fset.Position(ce.Pos()).Line, fset.Position(ce.End()).Line
				for _, mk := range fileMarkers {
					if mk.model == model && (mk.endOfNote >= start-1 && mk.endOfNote <= end || mk.line >= start && mk.line <= end) {
						mk.used = true
						return true
					}
				}
				findings = append(findings, fmt.Sprintf("%s:%d %s %s writes %s, whose full-row writer is exempt as SAFE-CAS in docs/full-row-write-exempt.tsv: check that the SAFE-CAS writer cannot revert this write (or this one revert it), then mark it `// %s %s: <why>` (or fix the writer and change its ledger row)", file, start, fn, sel.Sel.Name, model, safeCASWriterMarker, model))
				return true
			})
		}
	}
	for _, mk := range markers {
		if !mk.used {
			findings = append(findings, fmt.Sprintf("%s:%d marker for %s matches no write of that model on its line or right below it: remove it", mk.file, mk.line, mk.model))
		}
	}
	sort.Strings(findings)
	return findings
}

type safeCASChainInfo struct {
	model, table string
	gorm         bool
}

func (c *safeCASChainInfo) merge(in safeCASChainInfo) {
	c.gorm = c.gorm || in.gorm
	if c.model == "" {
		c.model = in.model
	}
	if c.table == "" {
		c.table = in.table
	}
}

// safeCASResolver resolves the table a receiver chain writes.
type safeCASResolver struct {
	env          *typeEnv
	assigned     map[string][]ast.Expr    // local variable -> every expression assigned to it
	tableToModel map[string]string        // table name -> model name
	helpers      map[string]*ast.FuncDecl // this package's functions returning *gorm.DB
}

// chain walks a receiver chain (x.A(...).B(...)) back to its root and reports the
// model named by Model(...), the table named by Table("..."), and whether the chain
// looks like gorm. A root that is a local variable is followed through its
// assignments in the same function, and a call of a same-package helper returning
// *gorm.DB through the helper's return statements. Arguments are not followed, so a
// subquery (Where("id IN (?)", db.Model(&models.Y{}))) does not name the written table.
func (r *safeCASResolver) chain(x ast.Expr, depth int) safeCASChainInfo {
	var out safeCASChainInfo
	for x != nil {
		switch v := x.(type) {
		case *ast.ParenExpr:
			x = v.X
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return out
			}
			name := sel.Sel.Name
			if safeCASGormChain[name] {
				out.gorm = true
			}
			switch {
			case name == "Model" && len(v.Args) == 1 && out.model == "":
				out.model = r.env.modelOf(v.Args[0])
				if out.model == "" {
					if lt := literalType(v.Args[0]); lt != nil {
						out.model = (&typeEnv{vars: map[string]ast.Expr{"_": lt}}).modelOf(ast.NewIdent("_"))
					}
				}
			case name == "Table" && len(v.Args) >= 1 && out.table == "":
				if s, ok := stringLiteral(v.Args[0]); ok {
					out.table, _, _ = strings.Cut(strings.TrimSpace(s), " ")
					if out.model == "" {
						out.model = r.tableToModel[out.table]
					}
				}
			case !safeCASGormChain[name] && r.helpers[name] != nil && depth < 4:
				out.gorm = true
				h := r.helpers[name]
				hr := &safeCASResolver{env: newTypeEnv(h), assigned: map[string][]ast.Expr{}, tableToModel: r.tableToModel, helpers: r.helpers}
				ast.Inspect(h.Body, func(n ast.Node) bool {
					hr.env.observe(n)
					if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
						for i, l := range as.Lhs {
							if id, ok := l.(*ast.Ident); ok {
								hr.assigned[id.Name] = append(hr.assigned[id.Name], as.Rhs[i])
							}
						}
					}
					if rs, ok := n.(*ast.ReturnStmt); ok && len(rs.Results) == 1 {
						out.merge(hr.chain(rs.Results[0], depth+1))
					}
					return true
				})
				return out
			}
			x = sel.X
		case *ast.SelectorExpr:
			if v.Sel.Name == "db" {
				out.gorm = true
			}
			return out
		case *ast.Ident:
			if v.Name == "tx" || v.Name == "db" {
				out.gorm = true
			}
			if depth >= 4 {
				return out
			}
			for _, rhs := range r.assigned[v.Name] {
				out.merge(r.chain(rhs, depth+1))
			}
			return out
		default:
			return out
		}
	}
	return out
}

// returnsGormDB: fd's only result is *gorm.DB.
func returnsGormDB(fd *ast.FuncDecl) bool {
	res := fd.Type.Results
	if res == nil || len(res.List) != 1 || len(res.List[0].Names) > 1 {
		return false
	}
	st, ok := res.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	se, ok := st.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := se.X.(*ast.Ident)
	return ok && pkg.Name == "gorm" && se.Sel.Name == "DB"
}

// stringLiteral returns the value of a string literal, or of a + concatenation of
// string literals.
func stringLiteral(x ast.Expr) (string, bool) {
	switch v := x.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, ok1 := stringLiteral(v.X)
		r, ok2 := stringLiteral(v.Y)
		return l + r, ok1 && ok2
	}
	return "", false
}

// TestFullRowWriteGuard_EveryOtherWriterOfASafeCASTableIsMarked is the guard.
func TestFullRowWriteGuard_EveryOtherWriterOfASafeCASTableIsMarked(t *testing.T) {
	g := guardrules.Rollout(t)
	cas := loadSafeCASLedger(t)
	require.NotEmpty(g, cas, "docs/full-row-write-exempt.tsv has no SAFE-CAS row: the ledger or its parser changed")
	tableToModel, modelToTable := modelTables(g)
	for m := range cas {
		require.NotEmptyf(g, modelToTable[m], "SAFE-CAS model %s is not in models.AllTestModels()", m)
	}
	findings := safeCASScan(g, ".", func(p string) string { return repoRelPath(t, p) }, cas, tableToModel)
	if len(findings) > 0 {
		g.Errorf("%d finding(s) on the tables of SAFE-CAS full-row writers:\n  %s", len(findings), strings.Join(findings, "\n  "))
	}
}

// TestFullRowWriteGuard_SafeCASWriterScanCalibration: the sweep reports each shape it
// claims to recognise, accepts a marked write and the ledgered writer itself, ignores
// other tables and subqueries, and refuses malformed and unused markers.
func TestFullRowWriteGuard_SafeCASWriterScanCalibration(t *testing.T) {
	dir := t.TempDir()
	src := `package store

func (ls *LocalStorage) TransitionMachineIdentityState(m *models.MachineIdentity) {
	ls.db.Model(&models.MachineIdentity{}).Where("id = ? AND state = ?", m.ID, "active").Select("*").Updates(m)
}

func (ls *LocalStorage) unmarkedMap(id uint) {
	ls.db.Model(&models.MachineIdentity{}).Where("id = ?", id).Updates(map[string]any{"state": "x"})
}

func (ls *LocalStorage) unmarkedViaVar(tx *gorm.DB, id uint) {
	q := tx.Model(&models.MachineIdentity{}).Where("id = ?", id)
	q = q.Where("state = ?", "active")
	q.Update("state", "suspended")
}

func (ls *LocalStorage) unmarkedTable(id uint) {
	ls.db.Table("machine_identities").Where("id = ?", id).UpdateColumn("name", "x")
}

func (ls *LocalStorage) unmarkedNew(id uint) {
	ls.db.Model(new(models.MachineIdentity)).Where("id = ?", id).Update("name", "x")
}

func (ls *LocalStorage) unmarkedExec(id uint) {
	ls.db.Exec("UPDATE machine_identities SET name = ? " + "WHERE id = ?", "x", id)
}

func (ls *LocalStorage) unmarkedArg(m *models.MachineIdentity) {
	ls.db.Updates(m)
}

func (ls *LocalStorage) marked(id uint) {
	// safe-cas-writer-ok: MachineIdentity: calibration fixture, moves state so the CAS misses
	ls.db.Model(&models.MachineIdentity{}).
		Where("id = ?", id).
		UpdateColumns(map[string]any{"state": "x"})
}

func (ls *LocalStorage) otherTableWithSubquery(id uint) {
	ls.db.Model(&models.Session{}).Where("id IN (?)", ls.db.Model(&models.MachineIdentity{}).Select("id")).Update("x", 1)
}

func (ls *LocalStorage) unresolved(q *gorm.DB) {
	q.Where("id = ?", 1).Update("x", 1)
}

func (ls *LocalStorage) machines(id uint) *gorm.DB {
	q := ls.db.Model(&models.MachineIdentity{})
	return q.Where("id = ?", id)
}

func (ls *LocalStorage) unmarkedViaHelper(id uint) {
	ls.machines(id).Update("name", "x")
}

func notGorm(h hasher) {
	h.Update([]byte("x"))
}

func (ls *LocalStorage) malformed(id uint) {
	// safe-cas-writer-ok: MachineIdentity: short
	ls.db.Model(&models.MachineIdentity{}).Where("id = ?", id).Update("x", 1)
}

// safe-cas-writer-ok: MachineIdentity: a marker with no write below it at all
func (ls *LocalStorage) unused() {}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600))
	cas := safeCASLedger{"MachineIdentity": {"x.go\t(*LocalStorage).TransitionMachineIdentityState": true}}
	tableToModel, _ := modelTables(t)
	got := safeCASScan(t, dir, filepath.Base, cas, tableToModel)
	joined := strings.Join(got, "\n")
	for _, fn := range []string{"unmarkedMap", "unmarkedViaVar", "unmarkedTable", "unmarkedNew", "unmarkedExec", "unmarkedArg", "unmarkedViaHelper"} {
		require.Containsf(t, joined, "(*LocalStorage)."+fn+" ", "the sweep missed the write in %s:\n%s", fn, joined)
	}
	require.Contains(t, joined, "(*LocalStorage).unresolved Update: cannot tell which table", "an unresolved gorm write must fail closed")
	require.Contains(t, joined, "malformed marker", "a marker with a too-short reason must be refused")
	require.Contains(t, joined, "(*LocalStorage).malformed Update writes MachineIdentity", "a malformed marker must not mark its write")
	require.Contains(t, joined, "matches no write of that model", "an unused marker must be reported")
	for _, fn := range []string{"TransitionMachineIdentityState", "marked", "otherTableWithSubquery", "notGorm"} {
		require.NotContainsf(t, joined, ")."+fn+" ", "false positive in %s:\n%s", fn, joined)
		require.NotContainsf(t, joined, " "+fn+" ", "false positive in %s:\n%s", fn, joined)
	}
	require.Len(t, got, 11, "one finding per planted defect:\n%s", joined)
}
