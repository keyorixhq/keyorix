// full_row_write_guard_test.go — C-GUARD-3 guard 1: no stale full-row write of
// a security-state model, in internal/storage/store or internal/core, unless
// the site is listed in docs/full-row-write-exempt.tsv with a reason.
//
// The bug class (#2648, #2650, #2653, #2654): an operation reads a row, checks
// something, then persists the WHOLE pre-read struct. GORM Save is an upsert
// (it resurrects a concurrently soft-deleted row) and Select("*").Updates
// writes every column (it reverts whatever a narrower concurrent writer — a
// suspension, a password change, a revoke — changed after the read). The
// fixed operations write only the columns they own (a map, or Select of named
// columns) through a conditional UPDATE.
//
// Two scans, both derived rather than hand-listed:
//
//  1. Primitive sites (internal/storage/store, non-test files): every call
//     `<x>.Save(arg)` and every call chain containing `Select("*")` followed
//     by `Updates(arg)`/`Update(...)`, where arg's static type is a
//     security-state model (see securityStateModels). Key:
//     `LocalStorage.<Method>  Save|SelectStar  <Model>`.
//  2. Caller sites (internal/storage/store and internal/core, non-test
//     files): every call `<recv>.<M>(...)` where M is a LocalStorage method
//     that scan 1 found doing a full-row write — a caller that hands such a
//     method its own pre-read struct is the stale write, even though the Save
//     itself lives one hop away (#2650: SetSecretAutoRotate → UpdateSecret).
//     Key: `<Func>  calls  <M>`.
//
// Every site found must have a row; every row must still match a site (a
// stale row fails too, so the file cannot quietly outlive its subject),
// except a row marked `pending: #N` / `ahead: #N` (see pendingPRRe).
//
// What this does NOT see, stated per CLAUDE.md ("ask of any mechanism: what
// does it silently skip"):
//   - It is syntactic. A Save's argument type is resolved from the enclosing
//     function's parameters, `var x T` and `x := T{}`/`&T{}`/`new(T)`
//     declarations only. An argument it cannot resolve is reported as model
//     "?" and must be exempted like any other hit (fails closed, not open).
//   - Caller scan 2 recognises calls by method NAME on any receiver except the
//     bare core receiver `c` (core methods share names with storage methods:
//     c.UpdateUser is the core method, c.storage.UpdateUser the primitive).
//     A call through a function value or an interface method with a
//     different name is invisible.
//   - Writes outside the two packages (server/http handlers, migrate, cli)
//     are not scanned.
//   - It does not check that a column-scoped write is ALSO conditional on
//     what the caller checked (INV-STORE-14 / the per-operation guards from
//     #2664/#2666/#2668 cover that for the fixed operations; they are not
//     folded in here — consolidation is a follow-up).
package store

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const fullRowWriteExemptFile = "../../../docs/full-row-write-exempt.tsv"

// securityStateFieldRe is the derivation rule for "security-state model": a
// model whose struct carries a soft-delete column (Save resurrects it) or any
// column whose name says it holds lifecycle, authorization or credential
// state (a stale write reverts it). The list of names is the only hand-written
// part; TestFullRowWriteGuard_DerivedModelSetCoversKnownClass pins that it
// still derives every model the 2026-10-03 review named.
var securityStateFieldRe = regexp.MustCompile(`^(DeletedAt|Is[A-Z]\w*|Status|State|AccountState|Disabled|Enabled|Revoked\w*|Expires\w*|Password\w*|Permission\w*|RoleID|Role|MFA\w*|Locked\w*|Suspended\w*|Approved\w*|Decision\w*|Decided\w*|Activated\w*|Verified\w*|Owner\w*|Secret|SecretHash|TokenHash|CredentialID|PublicKey|SignCount|Scope\w*|ProjectID|EnvironmentID|GroupID|UserID|Rotation\w*|AutoRotate\w*)$`)

// securityStateModels derives the security-state model set from
// models.AllTestModels() (the single source of truth for every GORM model) by
// reflection, returning model type name -> the fields that qualified it.
func securityStateModels() map[string][]string {
	out := map[string][]string{}
	for _, m := range models.AllTestModels() {
		t := reflect.TypeOf(m)
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		var why []string
		var walk func(reflect.Type)
		walk = func(t reflect.Type) {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if f.Anonymous && f.Type.Kind() == reflect.Struct {
					walk(f.Type)
					continue
				}
				if securityStateFieldRe.MatchString(f.Name) {
					why = append(why, f.Name)
				}
			}
		}
		walk(t)
		if len(why) > 0 {
			out[t.Name()] = why
		}
	}
	return out
}

type fullRowSite struct {
	key  string // tab-joined first three TSV columns
	file string
	line int
}

// chainHasSelectStar reports whether a method-call chain (the receiver side
// of an Updates call) contains Select("*").
func chainHasSelectStar(e ast.Expr) bool {
	for {
		ce, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if sel.Sel.Name == "Select" && len(ce.Args) == 1 {
			if bl, ok := ce.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, _ := strconv.Unquote(bl.Value); s == "*" {
					return true
				}
			}
		}
		e = sel.X
	}
}

// scanFullRowPrimitives is scan 1, over dir (relative to this package). It returns the sites and the set of
// LocalStorage method names that perform a full-row write.
func scanFullRowPrimitives(t *testing.T, dir string, sec map[string][]string) ([]fullRowSite, map[string]bool) {
	t.Helper()
	fset, files := parseNonTestGoFiles(t, dir)
	var sites []fullRowSite
	writers := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || len(ce.Args) == 0 {
					return true
				}
				var kind string
				switch {
				case sel.Sel.Name == "Save":
					kind = "Save"
				case (sel.Sel.Name == "Updates" || sel.Sel.Name == "Update") && chainHasSelectStar(sel.X):
					kind = "SelectStar"
				default:
					return true
				}
				arg := ce.Args[len(ce.Args)-1]
				if kind == "SelectStar" && sel.Sel.Name == "Updates" {
					arg = ce.Args[0]
				}
				model := fullRowArgModel(fd, arg)
				if model == "" {
					return true
				}
				if model != "?" {
					if _, isSec := sec[model]; !isSec {
						return true
					}
				}
				pos := fset.Position(ce.Pos())
				fn := strings.TrimPrefix(funcDisplayName(fd), "(*LocalStorage).")
				if fd.Recv != nil {
					fn = "LocalStorage." + fn
				}
				sites = append(sites, fullRowSite{key: fn + "\t" + kind + "\t" + model, file: pos.Filename, line: pos.Line})
				if strings.HasPrefix(fn, "LocalStorage.") {
					writers[fd.Name.Name] = true
				}
				return true
			})
		}
	}
	return sites, writers
}

// scanFullRowCallers is scan 2, over dir (relative to this package).
func scanFullRowCallers(t *testing.T, dir string, writers map[string]bool) []fullRowSite {
	t.Helper()
	fset, files := parseNonTestGoFiles(t, dir)
	var sites []fullRowSite
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || !writers[sel.Sel.Name] {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "c" {
					return true // the core method of the same name, not the primitive
				}
				// A primitive recursing into itself is its definition, not a
				// caller. A same-named method on another receiver (core's
				// UpdateGroup calling c.storage.UpdateGroup) IS a caller.
				if fd.Name.Name == sel.Sel.Name && funcDisplayName(fd) == "(*LocalStorage)."+fd.Name.Name {
					return true
				}
				pos := fset.Position(ce.Pos())
				sites = append(sites, fullRowSite{key: funcDisplayName(fd) + "\tcalls\t" + sel.Sel.Name, file: pos.Filename, line: pos.Line})
				return true
			})
		}
	}
	return sites
}

// fullRowExemptRow is one row of docs/full-row-write-exempt.tsv.
type fullRowExemptRow struct {
	key        string
	reason     string
	expires    string
	addedBy    string
	reviewedBy string
	line       int
}

// pendingPRRe marks a row tied to an open race-fix PR: `pending: #N` (the
// site disappears when #N merges — delete the row then) or `ahead: #N` (the
// site appears when #N merges — the row is pre-added so main stays green, and
// loses the marker then). Such rows are exempt from the stale-row check and
// must carry an expires date.
var pendingPRRe = regexp.MustCompile(`(pending|ahead): #(\d+)`)

func loadFullRowExempt(t *testing.T) map[string]fullRowExemptRow {
	t.Helper()
	f, err := os.Open(fullRowWriteExemptFile)
	if err != nil {
		t.Fatalf("open %s: %v", fullRowWriteExemptFile, err)
	}
	defer func() { _ = f.Close() }()
	rows := map[string]fullRowExemptRow{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	ln, header := 0, false
	for sc.Scan() {
		ln++
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if !header {
			want := "site\twrite\tmodel\treason\texpires\tadded_by\treviewed_by"
			if line != want {
				t.Fatalf("%s:%d: header must be %q, got %q", fullRowWriteExemptFile, ln, want, line)
			}
			header = true
			continue
		}
		if len(cols) != 7 {
			t.Fatalf("%s:%d: want 7 tab-separated columns, got %d", fullRowWriteExemptFile, ln, len(cols))
		}
		key := strings.Join(cols[:3], "\t")
		if _, dup := rows[key]; dup {
			t.Errorf("%s:%d: duplicate row %q", fullRowWriteExemptFile, ln, key)
		}
		if strings.TrimSpace(cols[3]) == "" {
			t.Errorf("%s:%d: row %q has no reason", fullRowWriteExemptFile, ln, key)
		}
		if strings.TrimSpace(cols[5]) == "" {
			t.Errorf("%s:%d: row %q has no added_by", fullRowWriteExemptFile, ln, key)
		}
		rows[key] = fullRowExemptRow{key: key, reason: cols[3], expires: cols[4], addedBy: cols[5], reviewedBy: cols[6], line: ln}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if !header {
		t.Fatalf("%s: no header row", fullRowWriteExemptFile)
	}
	return rows
}

func collectFullRowSites(t *testing.T) []fullRowSite {
	t.Helper()
	sec := securityStateModels()
	prims, writers := scanFullRowPrimitives(t, ".", sec)
	if len(writers) == 0 {
		t.Fatal("scan 1 found no full-row-writing LocalStorage method at all — either every one was fixed (then delete scan 2) or the scan stopped recognising them")
	}
	sites := append([]fullRowSite{}, prims...)
	sites = append(sites, scanFullRowCallers(t, ".", writers)...)
	sites = append(sites, scanFullRowCallers(t, "../../core", writers)...)
	return sites
}

// TestFullRowWriteGuard_NoUnexemptedStaleFullRowWrite is the guard.
func TestFullRowWriteGuard_NoUnexemptedStaleFullRowWrite(t *testing.T) {
	sites := collectFullRowSites(t)
	rows := loadFullRowExempt(t)
	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.key] = true
		if _, ok := rows[s.key]; !ok {
			t.Errorf("%s:%d: un-exempted full-row write of a security-state model: %q\n"+
				"  Write only the columns this operation owns (map, or Select of named columns) through a conditional UPDATE,\n"+
				"  or add a row to docs/full-row-write-exempt.tsv saying why a stale whole-row write is safe here.",
				s.file, s.line, strings.ReplaceAll(s.key, "\t", "  "))
		}
	}
	for k, r := range rows {
		if !seen[k] && !pendingPRRe.MatchString(r.reason) {
			t.Errorf("%s:%d: stale exemption %q: no such site any more — delete the row", fullRowWriteExemptFile, r.line, strings.ReplaceAll(k, "\t", "  "))
		}
	}
}

// TestFullRowWriteGuard_PendingRowsExpire fails once a `pending: #NNNN` row
// outlives its expiry date: the coordinator deletes a pending row when the
// race-fix PR it names lands; one that survives its expiry means that never
// happened. Offline and deterministic (the GitHub-backed "has the PR already
// merged" check is the generic one in internal/core's exemption-review guard).
func TestFullRowWriteGuard_PendingRowsExpire(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	for k, r := range loadFullRowExempt(t) {
		if pendingPRRe.MatchString(r.reason) && r.expires == "" {
			t.Errorf("%s:%d: pending row %q has no expires date", fullRowWriteExemptFile, r.line, k)
		}
		if r.expires != "" && r.expires < today {
			t.Errorf("%s:%d: row %q expired on %s — %s", fullRowWriteExemptFile, r.line, strings.ReplaceAll(k, "\t", "  "), r.expires, r.reason)
		}
	}
}

// TestFullRowWriteGuard_DerivedModelSetCoversKnownClass is the calibration
// for the derivation rule: every model the 2026-10-03 independent review
// (#2662) found written stale, or named as security state in the guard's
// brief, must come out of securityStateModels(). If the rule ever stops
// deriving one of them, the guard has silently narrowed.
func TestFullRowWriteGuard_DerivedModelSetCoversKnownClass(t *testing.T) {
	sec := securityStateModels()
	for _, m := range []string{"User", "ShareRecord", "SecretNode", "ProjectMembership", "MFASecret", "SecretACL", "UserRole", "MachineIdentity", "DynamicSecretConfig", "AccessReviewItem"} {
		if _, ok := sec[m]; !ok {
			t.Errorf("securityStateModels() no longer derives %s", m)
		}
	}
	names := make([]string, 0, len(sec))
	for n := range sec {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("derived %d security-state models: %s", len(sec), strings.Join(names, ", "))
}

// TestFullRowWriteGuard_ScanRecognisesBothShapes is the red direction on a
// planted fixture: the scan must report both a Save and a Select("*").Updates
// of a security-state model, resolve a parameter, a var and a := literal,
// and must NOT report a column-scoped Updates(map) or a non-model Save.
func TestFullRowWriteGuard_ScanRecognisesBothShapes(t *testing.T) {
	src := `package store
func (ls *LocalStorage) A(ctx context.Context, u *models.User) error { return ls.db.Save(u).Error }
func (ls *LocalStorage) B(ctx context.Context) error { var s models.ShareRecord; return ls.db.Save(&s).Error }
func (ls *LocalStorage) C(ctx context.Context, id uint) error { m := &models.ProjectMembership{}; return ls.db.Model(m).Where("id = ?", id).Select("*").Updates(m).Error }
func (ls *LocalStorage) D(ctx context.Context, id uint) error { return ls.db.Model(&models.User{}).Where("id = ?", id).Updates(map[string]any{"name": "x"}).Error }
func (ls *LocalStorage) E(ctx context.Context, x *other.Thing) error { return ls.db.Save(x).Error }
func (ls *LocalStorage) F(ctx context.Context, xs []*models.User) error { return ls.db.Save(xs[0]).Error }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	sites, writers := scanFullRowPrimitives(t, dir, securityStateModels())
	var got []string
	for _, s := range sites {
		got = append(got, s.key)
	}
	sort.Strings(got)
	want := []string{
		"LocalStorage.A\tSave\tUser",
		"LocalStorage.B\tSave\tShareRecord",
		"LocalStorage.C\tSelectStar\tProjectMembership",
		"LocalStorage.F\tSave\t?",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("scan on planted fixture:\n got  %q\n want %q", got, want)
	}
	if !writers["A"] || !writers["C"] || writers["D"] || writers["E"] {
		t.Fatalf("writers set wrong: %v", writers)
	}
}
