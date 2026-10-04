// parent_liveness_registry_test.go — C-GUARD-3 guard 2: every storage write
// that INSERTs (or un-deletes) a row whose model has a foreign key to a
// soft-deletable or disableable parent must, in the same transaction, re-check
// that parent with lockLiveParent (local_parent_liveness.go, INV-STORE-21), or
// be listed in docs/parent-liveness-exempt.tsv with a reason.
//
// The bug class (#2646, #2647, #2649, #2651, #2652, #2656): a child row (a
// share, an ACL grant, a lease, a restored environment, a config) commits
// under a parent another replica deleted between the caller's check and the
// insert, so the parent's delete cascade never sees it and it survives as live
// authority under a dead parent.
//
// Derived, not hand-maintained:
//   - parents: every model in models.AllTestModels() with a soft-delete column
//     (DeletedAt) or a disable/liveness flag (Disabled, IsActive);
//   - children: every model with a uint/*uint field ending in "ID" that
//     resolves (fkParentModel) to a parent. Every such field of every model
//     must resolve to a model or be listed in fkNotAParent — a new FK field
//     fails TestParentLivenessRegistry_EveryIDFieldClassified until it is;
//   - write sites: every function in this package's non-test files that
//     calls Create/FirstOrCreate with a child-model argument, or un-deletes a
//     child (a call chain with Model(&models.X{}) and Update("deleted_at", nil)).
//     GORM Save is deliberately NOT a write site here although its fallback
//     can INSERT: that fallback is exactly the stale-full-row resurrection
//     class, gated by guard 1 (full_row_write_guard_test.go) — counting it
//     twice would put one defect under two exemption ledgers.
//
// A row may use "*" for site (every site writing that child) and/or parent
// (every parent of that child): a model-level exemption, for a child whose
// rows carry no authority at all (an append-only audit/history record).
//
// A site is satisfied for one parent when the same function calls
// lockLiveParent(<h>, &models.<Parent>{}, ...) where <h> is the same root
// identifier the write was issued on (tx.Create + lockLiveParent(tx, ...)):
// that is the syntactic form of "in the same transaction".
//
// What this does NOT see:
//   - a write or a lockLiveParent call in a helper the write site calls (the
//     check is per function body; a helper-split site needs an exemption row
//     naming the helper);
//   - raw SQL INSERTs/UPDATEs (Exec/Raw), and a re-enable that flips a flag
//     other than deleted_at (e.g. TransitionDynamicSecretConfigDisabled
//     setting disabled=false — #2675 closes that one in core);
//   - whether lockLiveParent's WHERE actually names THIS child's parent row
//     (it checks the parent model, not the argument value), and whether the
//     write happens BEFORE the re-check as lockLiveParent's contract requires;
//   - argument types it cannot resolve syntactically (reported as model "?",
//     which never matches a child — stated, not silent: see
//     TestParentLivenessRegistry_ScanFixture).
package store

import (
	"bufio"
	"go/ast"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const parentLivenessExemptFile = "../../../docs/parent-liveness-exempt.tsv"

// parentPendingRe marks a row tied to an open race-fix PR, exactly as in
// docs/full-row-write-exempt.tsv: `pending: #N` (the site disappears when #N
// merges) or `ahead: #N` (it appears then). Such rows need an expires date
// and are exempt from the stale-row check.
var parentPendingRe = regexp.MustCompile(`(pending|ahead): #\d+`)

// fkAlias maps an FK field's stem (field name minus "ID") to the model it
// references when the stem is not itself the model's name.
var fkAlias = map[string]string{
	"Secret": "SecretNode", "Parent": "SecretNode", "DependentSecret": "SecretNode", "DependsOnSecret": "SecretNode",
	"Config": "DynamicSecretConfig", "Campaign": "AccessReviewCampaign", "Request": "AccessRequest",
	"Invitation": "ProjectInvitation", "Version": "SecretVersion", "Provider": "IdentityProvider",
	"Client": "APIClient", "Owner": "User", "Recipient": "User", "Approver": "User", "SubjectUser": "User",
	"OwnerMachineIdentity": "MachineIdentity", "CreatedByMachineIdentity": "MachineIdentity",
	"ClosedByMachineIdentity": "MachineIdentity", "InvitedByMachineIdentity": "MachineIdentity",
	"ResolvedByMachineIdentity": "MachineIdentity", "RevokedByMachineIdentity": "MachineIdentity",
	"ApproverMachineIdentity": "MachineIdentity",
}

// fkNotAParent lists "Model.Field" ID fields that are not a reference to a
// row whose liveness matters, with why.
var fkNotAParent = map[string]string{
	"AccessReviewItem.PrincipalID": "polymorphic (user or group per PrincipalType); a snapshot of who held a grant, not a live reference",
	"AuditCheckpoint.HeadID":       "an audit_events id (append-only, never deleted)",
}

func parentModels() map[string][]string {
	out := map[string][]string{}
	for _, m := range models.AllTestModels() {
		t := reflect.TypeOf(m).Elem()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			switch {
			case f.Name == "DeletedAt",
				(f.Name == "Disabled" || f.Name == "IsActive") && f.Type.Kind() == reflect.Bool:
				out[t.Name()] = append(out[t.Name()], f.Name)
			}
		}
	}
	return out
}

// fkParentModel resolves an ID field to the model name it references, "" if
// it is not an FK field, or "!" if it looks like one but is unclassified.
func fkParentModel(modelNames map[string]bool, model string, f reflect.StructField) string {
	k := f.Type.Kind()
	if k == reflect.Pointer {
		k = f.Type.Elem().Kind()
	}
	if f.Name == "ID" || !strings.HasSuffix(f.Name, "ID") || k != reflect.Uint {
		return ""
	}
	if _, ok := fkNotAParent[model+"."+f.Name]; ok {
		return ""
	}
	stem := strings.TrimSuffix(f.Name, "ID")
	if a, ok := fkAlias[stem]; ok {
		return a
	}
	if modelNames[stem] {
		return stem
	}
	return "!"
}

// childParents returns child model -> its parent models (deduplicated).
func childParents(t *testing.T) map[string][]string {
	t.Helper()
	parents := parentModels()
	names := map[string]bool{}
	for _, m := range models.AllTestModels() {
		names[reflect.TypeOf(m).Elem().Name()] = true
	}
	out := map[string][]string{}
	for _, m := range models.AllTestModels() {
		tt := reflect.TypeOf(m).Elem()
		seen := map[string]bool{}
		for i := 0; i < tt.NumField(); i++ {
			p := fkParentModel(names, tt.Name(), tt.Field(i))
			if p == "" || p == "!" || seen[p] {
				continue
			}
			if _, isParent := parents[p]; isParent {
				seen[p] = true
				out[tt.Name()] = append(out[tt.Name()], p)
			}
		}
		sort.Strings(out[tt.Name()])
	}
	return out
}

func TestParentLivenessRegistry_EveryIDFieldClassified(t *testing.T) {
	names := map[string]bool{}
	for _, m := range models.AllTestModels() {
		names[reflect.TypeOf(m).Elem().Name()] = true
	}
	for _, m := range models.AllTestModels() {
		tt := reflect.TypeOf(m).Elem()
		for i := 0; i < tt.NumField(); i++ {
			f := tt.Field(i)
			if p := fkParentModel(names, tt.Name(), f); p == "!" {
				t.Errorf("%s.%s looks like a foreign key but resolves to no model: add its stem to fkAlias, or the field to fkNotAParent with a reason", tt.Name(), f.Name)
			} else if p != "" && !names[p] {
				t.Errorf("%s.%s: fkAlias maps it to %q, which is not a model in AllTestModels", tt.Name(), f.Name, p)
			}
		}
	}
}

// rootIdent returns the leftmost identifier of a selector/call chain.
func rootIdent(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			e = v.X
		case *ast.CallExpr:
			e = v.Fun
		case *ast.ParenExpr:
			e = v.X
		default:
			return ""
		}
	}
}

// chainModel returns X for a Model(&models.X{}) / Model(models.X{}) call
// anywhere in a call chain, "" if none.
func chainModel(e ast.Expr) string {
	for {
		ce, ok := e.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if sel.Sel.Name == "Model" && len(ce.Args) == 1 {
			a := ce.Args[0]
			if u, ok := a.(*ast.UnaryExpr); ok && u.Op == token.AND {
				a = u.X
			}
			if cl, ok := a.(*ast.CompositeLit); ok {
				return modelsTypeName(cl.Type)
			}
		}
		e = sel.X
	}
}

type parentWrite struct {
	fn, child, op, root string
	file                string
	line                int
}

// scanChildWrites finds every insert/un-delete of a model in children, and
// every lockLiveParent(root, &models.P{}) call, per function, in dir.
func scanChildWrites(t *testing.T, dir string, children map[string][]string) ([]parentWrite, map[string]map[string]bool) {
	t.Helper()
	fset, files := parseNonTestGoFiles(t, dir)
	var writes []parentWrite
	locks := map[string]map[string]bool{} // fn -> "root\tParent"
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := funcDisplayName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "lockLiveParent" && len(ce.Args) >= 2 {
					if p := fullRowArgModel(fd, ce.Args[1]); p != "" && p != "?" {
						if locks[fn] == nil {
							locks[fn] = map[string]bool{}
						}
						locks[fn][rootIdent(ce.Args[0])+"\t"+p] = true
					}
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || len(ce.Args) == 0 {
					return true
				}
				var model, op string
				switch sel.Sel.Name {
				case "Create", "FirstOrCreate":
					model, op = fullRowArgModel(fd, ce.Args[0]), sel.Sel.Name
				case "Update":
					if bl, ok := ce.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING && len(ce.Args) == 2 {
						if s, _ := strconv.Unquote(bl.Value); s == "deleted_at" {
							if id, ok := ce.Args[1].(*ast.Ident); ok && id.Name == "nil" {
								model, op = chainModel(sel.X), "Undelete"
							}
						}
					}
				}
				if _, isChild := children[model]; !isChild {
					return true
				}
				pos := fset.Position(ce.Pos())
				writes = append(writes, parentWrite{fn: fn, child: model, op: op, root: rootIdent(sel.X), file: pos.Filename, line: pos.Line})
				return true
			})
		}
	}
	return writes, locks
}

type parentExemptRow struct {
	reason, expires, addedBy, reviewedBy string
	line                                 int
}

func loadParentLivenessExempt(t *testing.T) map[string]parentExemptRow {
	t.Helper()
	f, err := os.Open(parentLivenessExemptFile)
	if err != nil {
		t.Fatalf("open %s: %v", parentLivenessExemptFile, err)
	}
	defer func() { _ = f.Close() }()
	rows := map[string]parentExemptRow{}
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
			want := "site\tchild\tparent\treason\texpires\tadded_by\treviewed_by"
			if line != want {
				t.Fatalf("%s:%d: header must be %q, got %q", parentLivenessExemptFile, ln, want, line)
			}
			header = true
			continue
		}
		if len(cols) != 7 {
			t.Fatalf("%s:%d: want 7 tab-separated columns, got %d", parentLivenessExemptFile, ln, len(cols))
		}
		key := strings.Join(cols[:3], "\t")
		if _, dup := rows[key]; dup {
			t.Errorf("%s:%d: duplicate row %q", parentLivenessExemptFile, ln, key)
		}
		if strings.TrimSpace(cols[3]) == "" || strings.TrimSpace(cols[5]) == "" {
			t.Errorf("%s:%d: row %q needs a reason and added_by", parentLivenessExemptFile, ln, key)
		}
		rows[key] = parentExemptRow{reason: cols[3], expires: cols[4], addedBy: cols[5], reviewedBy: cols[6], line: ln}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if !header {
		t.Fatalf("%s: no header row", parentLivenessExemptFile)
	}
	return rows
}

// TestParentLivenessRegistry_EveryChildWriteRechecksItsParents is the guard.
func TestParentLivenessRegistry_EveryChildWriteRechecksItsParents(t *testing.T) {
	children := childParents(t)
	writes, locks := scanChildWrites(t, ".", children)
	if len(writes) < 20 {
		t.Fatalf("found only %d child-row writes — the scan stopped seeing them", len(writes))
	}
	rows := loadParentLivenessExempt(t)
	seen := map[string]bool{}
	for _, w := range writes {
		for _, p := range children[w.child] {
			if locks[w.fn][w.root+"\t"+p] {
				continue
			}
			key := w.fn + "\t" + w.child + "\t" + p
			matched := ""
			for _, k := range []string{key, "*\t" + w.child + "\t" + p, w.fn + "\t" + w.child + "\t*", "*\t" + w.child + "\t*"} {
				if _, ok := rows[k]; ok {
					matched = k
					break
				}
			}
			if matched != "" {
				seen[matched] = true
			} else {
				t.Errorf("%s:%d: %s %ss a %s row (FK to soft-deletable/disableable %s) without lockLiveParent(%s, &models.%s{}, ...) in the same function and transaction.\n"+
					"  Re-check the parent after the write (local_parent_liveness.go), or add a row to docs/parent-liveness-exempt.tsv:\n  %s",
					w.file, w.line, w.fn, strings.ToLower(w.op), w.child, p, w.root, p, strings.ReplaceAll(key, "\t", "  "))
			}
		}
	}
	for k, r := range rows {
		if !seen[k] && !parentPendingRe.MatchString(r.reason) {
			t.Errorf("%s:%d: stale exemption %q: the site now re-checks that parent, or no longer exists — delete the row", parentLivenessExemptFile, r.line, strings.ReplaceAll(k, "\t", "  "))
		}
	}
}

// TestParentLivenessRegistry_PendingRowsExpire: see the same-named full-row
// guard test; a `pending: #NNNN` row must carry an expiry and not outlive it.
func TestParentLivenessRegistry_PendingRowsExpire(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	for k, r := range loadParentLivenessExempt(t) {
		if parentPendingRe.MatchString(r.reason) && r.expires == "" {
			t.Errorf("%s:%d: pending row %q has no expires date", parentLivenessExemptFile, r.line, k)
		}
		if r.expires != "" && r.expires < today {
			t.Errorf("%s:%d: row %q expired on %s — %s", parentLivenessExemptFile, r.line, strings.ReplaceAll(k, "\t", "  "), r.expires, r.reason)
		}
	}
}

// TestParentLivenessRegistry_DerivesKnownClass calibrates the derivation
// against the six 2026-10-03 findings: each child/parent pair they fixed must
// be derived, or the registry has silently narrowed.
func TestParentLivenessRegistry_DerivesKnownClass(t *testing.T) {
	children := childParents(t)
	has := func(child, parent string) bool {
		for _, p := range children[child] {
			if p == parent {
				return true
			}
		}
		return false
	}
	for _, c := range [][2]string{
		{"ShareRecord", "SecretNode"},                 // #2646, #2647
		{"SecretACL", "SecretNode"},                   // #2649
		{"DynamicSecretConfig", "Project"},            // #2651
		{"DynamicSecretLease", "DynamicSecretConfig"}, // #2652
		{"Environment", "Project"},                    // #2656
	} {
		if !has(c[0], c[1]) {
			t.Errorf("childParents() no longer derives %s -> %s", c[0], c[1])
		}
	}
}

// TestParentLivenessRegistry_ScanFixture is the red direction on a planted
// fixture: an unchecked insert, a checked one, a check on the wrong handle,
// and an un-delete must be classified exactly as below.
func TestParentLivenessRegistry_ScanFixture(t *testing.T) {
	src := `package store
func (ls *LocalStorage) A(ctx context.Context, a *models.SecretACL) error { return ls.db.Create(a).Error }
func (ls *LocalStorage) B(ctx context.Context, a *models.SecretACL) error {
	return ls.db.Transaction(func(tx *gorm.DB) error { if err := tx.Create(a).Error; err != nil { return err }; _, err := lockLiveParent(tx, &models.SecretNode{}, "id = ?", a.SecretID); return err })
}
func (ls *LocalStorage) C(ctx context.Context, a *models.SecretACL) error {
	return ls.db.Transaction(func(tx *gorm.DB) error { if err := ls.db.Create(a).Error; err != nil { return err }; _, err := lockLiveParent(tx, &models.SecretNode{}, "id = ?", a.SecretID); return err })
}
func (ls *LocalStorage) D(ctx context.Context, id uint) error { return ls.db.Unscoped().Model(&models.Environment{}).Where("id = ?", id).Update("deleted_at", nil).Error }
`
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/x.go", []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	children := childParents(t)
	writes, locks := scanChildWrites(t, dir, children)
	var got []string
	for _, w := range writes {
		for _, p := range children[w.child] {
			got = append(got, w.fn+" "+w.op+" "+w.child+"->"+p+" locked="+strconv.FormatBool(locks[w.fn][w.root+"\t"+p]))
		}
	}
	sort.Strings(got)
	want := []string{
		"(*LocalStorage).A Create SecretACL->SecretNode locked=false",
		"(*LocalStorage).A Create SecretACL->User locked=false",
		"(*LocalStorage).B Create SecretACL->SecretNode locked=true",
		"(*LocalStorage).B Create SecretACL->User locked=false",
		"(*LocalStorage).C Create SecretACL->SecretNode locked=false",
		"(*LocalStorage).C Create SecretACL->User locked=false",
		"(*LocalStorage).D Undelete Environment->Project locked=false",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("scan on planted fixture:\n got:\n%s\n want:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
