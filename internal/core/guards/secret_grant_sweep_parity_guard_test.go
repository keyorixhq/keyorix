package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
)

// REVOKE-GUARDS-NOV-1 item 2: the per-secret grant-table parity guard.
//
// #2798 (deleteProjectCascade swept ShareRecord but not SecretACL) and #2797
// (neither path closed approved secret-scoped AccessRequests) are the same
// defect: a per-secret grant table that one delete path sweeps and its sibling
// forgets, so the grant comes back on RestoreSecret / RestoreProject with no
// re-authorization. This guard derives both sides instead of listing them:
//
//   - the population is every table, from internal/storage.AllModels() by gorm
//     schema reflection, with a column named secret_id;
//   - each path's sweep set is the models it references (models.X composite
//     literals) in its body and, transitively, in the package-level functions
//     and LocalStorage methods of internal/storage/store it calls
//     (closeApprovedSecretAccessRequests is how AccessRequest is reached).
//
// It asserts: DeleteSecret and deleteProjectCascade sweep the same per-secret
// tables; every per-secret table is swept, or exempt with a reason in
// testdata/secret_id_table_exempt.d (a table that carries secret_id but grants nothing); an
// exemption is still a per-secret table and still unswept. A new per-secret
// grant table is therefore red until DeleteSecret sweeps it, and then red until
// deleteProjectCascade does too.
//
// What this does not check: that a referenced model is actually deleted or
// closed for the right rows (the behavioural tests in internal/storage/store
// local_lifecycle_cascade_test.go do that per table), raw-SQL-only sweeps with
// no models.X literal, and grant tables keyed by another column name
// (secret_node_id tables are secret data and history, not grants).

const storeDir = "../../storage/store"

// secretIDTableExemptDir holds the tables with a secret_id column that are not
// grants, so neither delete path sweeps them: one file per table
// (testdata/secret_id_table_exempt.d/<table>.tsv, row `table<TAB>reason`), so a PR
// edits only its own table's file. See the README.md in the directory.
const secretIDTableExemptDir = "testdata/secret_id_table_exempt.d"

// loadSecretIDTableExempt reads table -> reason from every *.tsv in dir. A file
// holds exactly one row and is named for its table, so a table cannot sit in two
// files.
//
// dir-listing-ok: the exemption fragments in testdata, not internal/core's sources
func loadSecretIDTableExempt(t testing.TB, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(filepath.FromSlash(dir))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tsv") {
			continue // README.md
		}
		b, err := os.ReadFile(filepath.Join(filepath.FromSlash(dir), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var rows [][2]string
		for i, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
				continue
			}
			table, reason, ok := strings.Cut(line, "\t")
			if !ok || strings.TrimSpace(table) == "" || strings.TrimSpace(reason) == "" {
				t.Fatalf("%s:%d: want `table<TAB>reason` with a non-empty reason, got %q", e.Name(), i+1, line)
			}
			rows = append(rows, [2]string{table, strings.TrimSpace(reason)})
		}
		if len(rows) != 1 {
			t.Fatalf("%s: holds %d rows; a fragment holds exactly one", e.Name(), len(rows))
		}
		if want := rows[0][0] + ".tsv"; e.Name() != want {
			t.Fatalf("%s: the row for table %q must live in a file named %s", e.Name(), rows[0][0], want)
		}
		out[rows[0][0]] = rows[0][1]
	}
	return out
}

// secretIDTables returns, sorted, the struct name -> table name of every model
// in AllModels with a column named secret_id.
func secretIDTables(t testing.TB) map[string]string {
	t.Helper()
	out := map[string]string{}
	cache := &sync.Map{}
	for _, m := range kxstorage.AllModels() {
		s, err := schema.Parse(m, cache, schema.NamingStrategy{})
		if err != nil {
			t.Fatalf("parse model %T: %v", m, err)
		}
		if s.LookUpField("secret_id") != nil {
			out[s.Name] = s.Table
		}
	}
	return out
}

// storeFuncIndex maps a store function name (package-level func, or LocalStorage
// method keyed "ls.Name") to its declaration, over the given source files.
func storeFuncIndex(t testing.TB, files map[string]string) map[string]*ast.FuncDecl {
	t.Helper()
	idx := map[string]*ast.FuncDecl{}
	fset := token.NewFileSet()
	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			key := fd.Name.Name
			if fd.Recv != nil {
				key = "ls." + key
			}
			idx[key] = fd
		}
	}
	return idx
}

// sweptModels returns the models.X struct names referenced by root and every
// store function it reaches by a plain call (f(...)) or a receiver call
// (ls.f(...) on its own receiver).
func sweptModels(idx map[string]*ast.FuncDecl, root string) map[string]bool {
	seen := map[string]bool{}
	models := map[string]bool{}
	var walk func(key string)
	walk = func(key string) {
		fd, ok := idx[key]
		if !ok || seen[key] {
			return
		}
		seen[key] = true
		recv := ""
		if fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 {
			recv = fd.Recv.List[0].Names[0].Name
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CompositeLit:
				if sel, ok := v.Type.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "models" {
						models[sel.Sel.Name] = true
					}
				}
			case *ast.CallExpr:
				switch fn := v.Fun.(type) {
				case *ast.Ident:
					walk(fn.Name)
				case *ast.SelectorExpr:
					if x, ok := fn.X.(*ast.Ident); ok && recv != "" && x.Name == recv {
						walk("ls." + fn.Sel.Name)
					}
				}
			}
			return true
		})
	}
	walk(root)
	return models
}

// secretSweepParityViolations is the whole check over a store source set, a
// population (struct -> table) and an exemption map; empty means it holds.
func secretSweepParityViolations(t testing.TB, files map[string]string, population map[string]string, exempt map[string]string) []string {
	t.Helper()
	idx := storeFuncIndex(t, files)
	for _, root := range []string{"ls.DeleteSecret", "deleteProjectCascade"} {
		if _, ok := idx[root]; !ok {
			return []string{root + " not found in internal/storage/store: renamed? re-point this guard"}
		}
	}
	single := sweptModels(idx, "ls.DeleteSecret")
	cascade := sweptModels(idx, "deleteProjectCascade")
	var out []string
	structs := slices.Sorted(func(yield func(string) bool) {
		for k := range population {
			if !yield(k) {
				return
			}
		}
	})
	tables := map[string]bool{}
	for _, st := range structs {
		table := population[st]
		tables[table] = true
		inSingle, inCascade := single[st], cascade[st]
		switch {
		case inSingle && !inCascade:
			out = append(out, "DeleteSecret sweeps per-secret table "+table+" ("+st+") but deleteProjectCascade does not: its rows come back live on RestoreProject")
		case inCascade && !inSingle:
			out = append(out, "deleteProjectCascade sweeps per-secret table "+table+" ("+st+") but DeleteSecret does not: its rows come back live on RestoreSecret")
		case !inSingle && !inCascade:
			if reason, ok := exempt[table]; !ok {
				out = append(out, "per-secret table "+table+" ("+st+") carries secret_id and neither DeleteSecret nor deleteProjectCascade sweeps it: "+
					"if it grants access, sweep it in both; otherwise add testdata/secret_id_table_exempt.d/"+table+".tsv with the reason it grants nothing")
			} else if strings.TrimSpace(reason) == "" {
				out = append(out, "secret_id_table_exempt.d/"+table+".tsv has no reason")
			}
		default:
			if _, ok := exempt[table]; ok {
				out = append(out, "secret_id_table_exempt.d lists "+table+", which both paths now sweep: delete "+table+".tsv")
			}
		}
	}
	for table := range exempt {
		if !tables[table] {
			out = append(out, "secret_id_table_exempt.d lists "+table+", which is no longer a table with a secret_id column: delete "+table+".tsv")
		}
	}
	slices.Sort(out)
	return out
}

// readStoreSources returns every non-test .go file of internal/storage/store.
// dir-listing-ok: lists internal/storage/store, not core sources
func readStoreSources(t testing.TB) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(filepath.FromSlash(storeDir))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(filepath.FromSlash(storeDir), n))
		if err != nil {
			t.Fatal(err)
		}
		files[n] = string(b)
	}
	if len(files) < 20 {
		t.Fatalf("only %d store source files under %s: wrong root", len(files), storeDir)
	}
	return files
}

// knownSecretGrantTables are the three per-secret grant tables the sweeps were
// fixed for (#370, CWE-284/#2798, #2797): the vacuity floor of the derivation.
var knownSecretGrantTables = []string{"ShareRecord", "SecretACL", "AccessRequest"}

func TestSecretGrantSweep_DeleteSecretAndProjectCascadeSweepTheSameTables(t *testing.T) {
	g := guardrules.Rollout(t)
	population := secretIDTables(t)
	for _, k := range knownSecretGrantTables {
		if _, ok := population[k]; !ok {
			t.Fatalf("reflection found no secret_id column on %s (population %v): the derivation is broken", k, population)
		}
	}
	files := readStoreSources(t)
	idx := storeFuncIndex(t, files)
	single := sweptModels(idx, "ls.DeleteSecret")
	for _, k := range knownSecretGrantTables {
		if !single[k] {
			t.Fatalf("the sweep derivation does not see DeleteSecret reach %s (got %v): the call-following is broken", k, single)
		}
	}
	exempt := loadSecretIDTableExempt(t, secretIDTableExemptDir)
	t.Logf("per-secret tables (secret_id): %v; exempt: %v", population, slices.Sorted(func(yield func(string) bool) {
		for k := range exempt {
			if !yield(k) {
				return
			}
		}
	}))
	if v := secretSweepParityViolations(t, files, population, exempt); len(v) > 0 {
		g.Errorf("per-secret grant sweep parity:\n  %s", strings.Join(v, "\n  "))
	}
}

// TestSecretGrantSweep_Calibration plants store sources against the real
// population: a third per-secret table swept by DeleteSecret only (the #2798
// shape) and by the cascade only must go red; an unswept, unexempted per-secret
// table must go red; the real sweep set with both sides equal is green.
func TestSecretGrantSweep_Calibration(t *testing.T) {
	population := secretIDTables(t)
	const helper = `package store
func closeApproved(tx *gorm.DB) error { return tx.Model(&models.AccessRequest{}).Error }
`
	mk := func(singleExtra, cascadeExtra string) map[string]string {
		return map[string]string{
			"planted helper": helper,
			"planted delete": `package store
func (ls *LocalStorage) DeleteSecret(ctx context.Context, id uint) error {
	tx.Delete(&models.SecretNode{}, id)
	tx.Delete(&models.ShareRecord{})
	tx.Delete(&models.SecretACL{})
	` + singleExtra + `
	return ls.other(tx)
}
func (ls *LocalStorage) other(tx *gorm.DB) error { return closeApproved(tx) }
`,
			"planted cascade": `package store
func deleteProjectCascade(tx *gorm.DB, id uint, d int) error {
	tx.Delete(&models.ShareRecord{})
	tx.Delete(&models.SecretACL{})
	` + cascadeExtra + `
	return closeApproved(tx)
}
`,
		}
	}
	third := `tx.Delete(&models.SecretVersionComment{})`
	exemptWithoutThird := map[string]string{"access_review_items": "x"}
	realExempt := loadSecretIDTableExempt(t, secretIDTableExemptDir)

	if v := secretSweepParityViolations(t, mk("", ""), population, realExempt); len(v) != 0 {
		t.Fatalf("green case: the real sweep set on both sides must pass, got %v", v)
	}
	for _, tc := range []struct {
		name, single, cascade string
		exempt                map[string]string
		want                  string
	}{
		{"third_table_single_only", third, "", exemptWithoutThird, "DeleteSecret sweeps per-secret table secret_version_comments"},
		{"third_table_cascade_only", "", third, exemptWithoutThird, "deleteProjectCascade sweeps per-secret table secret_version_comments"},
		{"third_table_unswept_unexempt", "", "", exemptWithoutThird, "per-secret table secret_version_comments (SecretVersionComment) carries secret_id and neither"},
		{"acl_dropped_from_cascade", "", "", realExempt, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := mk(tc.single, tc.cascade)
			if tc.name == "acl_dropped_from_cascade" {
				// The literal #2798 regression: the cascade without its SecretACL sweep.
				files["planted cascade"] = strings.Replace(files["planted cascade"], "tx.Delete(&models.SecretACL{})", "", 1)
				tc.want = "DeleteSecret sweeps per-secret table secret_acls"
			}
			got := strings.Join(secretSweepParityViolations(t, files, population, tc.exempt), "\n")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("planted %s: want a violation containing %q, got:\n%s", tc.name, tc.want, got)
			}
		})
	}
}
