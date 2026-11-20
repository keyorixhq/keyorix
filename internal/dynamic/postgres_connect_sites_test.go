package dynamic

// postgres_connect_sites_test.go — every pgx connection internal/dynamic opens
// toward an admin_dsn host must be built by connectPostgres, because that is the
// one place pgxlimits.Apply is called (see postgres_max_body_len_test.go for why
// the bound exists). A second, direct pgx.Connect* call in this package would
// silently reintroduce the unbounded server-claimed allocation, and no
// behavioural test of the existing engines would notice.
//
// Recognised idioms, all by import path so aliases do not hide them: ANY
// reference (a call, or a function value such as f := pgx.ConnectConfig or
// retry(pgx.ConnectConfig)) to a name in pgxConnectFuncs through an import of
// github.com/jackc/pgx/v5, .../pgconn, .../pgxpool, .../stdlib or .../pgproto3;
// a dot import of any of those; database/sql.Open with the driver literal "pgx" or
// "pgx/v5" (stdlib registers both) or with a non-literal driver name. The list of
// names was taken from those packages' exported functions that dial a server or
// wrap an already-dialled connection; a reviewer should extend it when pgx grows
// another.
//
// sql.OpenDB is only judged in files that import pgx: openMySQLConfig legitimately
// calls it with a MySQL connector, and a pgx connector built in another file and
// passed in is not visible here.
//
// What this does NOT cover: a pgx connect inside a helper in another package that
// internal/dynamic calls (none exists today), other packages (internal/storage, internal/auditverify,
// internal/rotation and server/admin open their own connections against
// operator-trusted databases and are out of scope here), subpackages of
// internal/dynamic, whether Apply runs BEFORE the connect on the same config or is
// overwritten afterwards (the behavioural test covers that for Issue, Renew and
// Revoke), and a connect reached through reflection or an interface value built
// elsewhere.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var pgxImportPaths = map[string]bool{
	"github.com/jackc/pgx/v5":          true,
	"github.com/jackc/pgx/v5/pgconn":   true,
	"github.com/jackc/pgx/v5/pgxpool":  true,
	"github.com/jackc/pgx/v5/stdlib":   true,
	"github.com/jackc/pgx/v5/pgproto3": true,
}

const pgxlimitsPath = "github.com/keyorixhq/keyorix/internal/pgxlimits"

var pgxConnectFuncs = map[string]bool{
	"Connect": true, "ConnectConfig": true, "ConnectWithOptions": true,
	"New": true, "NewWithConfig": true,
	"OpenDB": true, "Open": true, "GetConnector": true, "OpenDBFromPool": true,
	"Construct": true, "NewFrontend": true,
}

type pgxSite struct{ Fn, Call string }

// pgxConnectSites lists every recognised pgx connect idiom in src (file name ->
// source) and whether connectPostgres calls pgxlimits.Apply.
func pgxConnectSites(t testing.TB, src map[string]string) (sites []pgxSite, setsBound bool) {
	t.Helper()
	fset := token.NewFileSet()
	for _, name := range slices.Sorted(maps.Keys(src)) {
		f, err := parser.ParseFile(fset, name, src[name], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		local := map[string]string{}
		importsPgx := false
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !pgxImportPaths[path] && path != "database/sql" && path != pgxlimitsPath {
				continue
			}
			importsPgx = importsPgx || pgxImportPaths[path]
			n := path[strings.LastIndex(path, "/")+1:]
			if n == "v5" { // github.com/jackc/pgx/v5 declares package pgx
				n = "pgx"
			}
			if imp.Name != nil {
				n = imp.Name.Name
			}
			if n == "." && pgxImportPaths[path] {
				sites = append(sites, pgxSite{"<imports>", ". import of " + path})
				continue
			}
			local[n] = path
		}
		for _, d := range f.Decls {
			fn := "<package-level>"
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
				if fd.Recv != nil { // a method named connectPostgres is not THE connectPostgres
					fn = "(method)." + fn
				}
			}
			called := map[*ast.SelectorExpr]bool{} // selectors that are the callee of a call
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					id, ok := x.X.(*ast.Ident)
					if !ok {
						return true
					}
					path := local[id.Name]
					if pgxImportPaths[path] && pgxConnectFuncs[x.Sel.Name] {
						sites = append(sites, pgxSite{fn, id.Name + "." + x.Sel.Name})
					}
					if path == "database/sql" && !called[x] && (x.Sel.Name == "Open" || (x.Sel.Name == "OpenDB" && importsPgx)) {
						// sql.OpenDB(connector) dials through a connector built elsewhere, and
						// `open := sql.Open` hides the driver name: neither can be judged, so both are sites.
						sites = append(sites, pgxSite{fn, "sql." + x.Sel.Name + " (not a direct call)"})
					}
				case *ast.CallExpr:
					se, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					called[se] = true
					id, ok := se.X.(*ast.Ident)
					if !ok {
						return true
					}
					if local[id.Name] == pgxlimitsPath && se.Sel.Name == "Apply" && fn == "connectPostgres" {
						setsBound = true // a real call, not a bare mention of the function
					}
					if local[id.Name] == "database/sql" && se.Sel.Name == "OpenDB" && importsPgx {
						sites = append(sites, pgxSite{fn, "sql.OpenDB"})
					}
					if len(x.Args) == 0 || local[id.Name] != "database/sql" || se.Sel.Name != "Open" {
						return true
					}
					lit, isLit := x.Args[0].(*ast.BasicLit)
					drv := ""
					if isLit {
						drv = strings.Trim(lit.Value, "\"`")
					}
					if !isLit || drv == "pgx" || drv == "pgx/v5" {
						sites = append(sites, pgxSite{fn, "sql.Open(" + map[bool]string{true: drv, false: "non-literal driver"}[isLit] + ")"})
					}
				}
				return true
			})
		}
	}
	return sites, setsBound
}

func TestEveryPgxConnectInDynamicUsesTheBoundedConfig(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src[f] = string(b)
	}
	sites, setsBound := pgxConnectSites(t, src)

	if len(sites) == 0 {
		t.Fatal("found no pgx connect site in internal/dynamic: either the guard no longer recognises the idiom " +
			"connectPostgres uses, or the connection moved; a guard that sees nothing proves nothing")
	}
	for _, s := range sites {
		if s.Fn != "connectPostgres" {
			t.Errorf("%s is used in %s: pgx connections toward an admin_dsn host must be built by connectPostgres, "+
				"which applies pgxlimits.Apply", s.Call, s.Fn)
		}
	}
	if !setsBound {
		t.Error("connectPostgres no longer calls pgxlimits.Apply")
	}
}

// TestPgxConnectSiteGuardFiresOnPlantedViolations is the red/green calibration for
// the guard above, run on synthetic sources so no production file is edited.
func TestPgxConnectSiteGuardFiresOnPlantedViolations(t *testing.T) {
	const ok = `package dynamic
import (
	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/pgxlimits"
)
func connectPostgres(cfg *pgx.ConnConfig) { pgxlimits.Apply(cfg); pgx.ConnectConfig(nil, cfg) }`
	sites, bound := pgxConnectSites(t, map[string]string{"ok.go": ok})
	if len(sites) != 1 || sites[0].Fn != "connectPostgres" || !bound {
		t.Fatalf("GREEN: bounded connectPostgres must be accepted, got sites=%v bound=%v", sites, bound)
	}

	if got, _ := pgxConnectSites(t, map[string]string{"mysql.go": `package dynamic
import "database/sql"
func openMySQL() { sql.OpenDB(nil) }`}); len(got) != 0 {
		t.Fatalf("GREEN: sql.OpenDB in a file that does not import pgx must be accepted, got %v", got)
	}

	// Each planted violation sits in its own function so the expectation is exact.
	red := map[string]string{
		"direct.go": `package dynamic
import "github.com/jackc/pgx/v5"
func other() { pgx.Connect(nil, "") }`,
		"aliased.go": `package dynamic
import pg "github.com/jackc/pgx/v5"
func aliased() { pg.ConnectConfig(nil, nil) }`,
		"pool.go": `package dynamic
import "github.com/jackc/pgx/v5/pgxpool"
var p, _ = pgxpool.New(nil, "")`,
		"stdlib.go": `package dynamic
import "database/sql"
func viaSQL() { sql.Open("pgx", "") }`,
		"stdlibv5.go": `package dynamic
import "database/sql"
func viaSQLv5() { sql.Open("pgx/v5", "") }`,
		"nonliteral.go": `package dynamic
import "database/sql"
func viaVar(driver string) { sql.Open(driver, "") }`,
		"funcvalue.go": `package dynamic
import "github.com/jackc/pgx/v5"
func asValue() { f := pgx.ConnectConfig; _ = f }`,
		"connector.go": `package dynamic
import "github.com/jackc/pgx/v5/stdlib"
func viaConnector() { stdlib.GetConnector(nil) }`,
		"frontend.go": `package dynamic
import "github.com/jackc/pgx/v5/pgproto3"
func rawFrontend() { pgproto3.NewFrontend(nil, nil) }`,
		"openvalue.go": `package dynamic
import "database/sql"
func openValue() { open := sql.Open; _ = open }`,
		"opendb.go": `package dynamic
import (
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
)
func viaOpenDB() { sql.OpenDB(nil) }`,
		"method.go": `package dynamic
import "github.com/jackc/pgx/v5"
type T struct{}
func (T) connectPostgres() { pgx.Connect(nil, "") }`,
		"dot.go": `package dynamic
import . "github.com/jackc/pgx/v5/pgconn"
func dotted() { _ = Connect }`,
	}
	want := map[string]string{
		"other": "pgx.Connect", "aliased": "pg.ConnectConfig", "<package-level>": "pgxpool.New",
		"viaSQL": "sql.Open(pgx)", "viaSQLv5": "sql.Open(pgx/v5)", "viaVar": "sql.Open(non-literal driver)",
		"asValue": "pgx.ConnectConfig", "viaConnector": "stdlib.GetConnector", "rawFrontend": "pgproto3.NewFrontend",
		"<imports>": ". import of github.com/jackc/pgx/v5/pgconn",
		"openValue": "sql.Open (not a direct call)", "viaOpenDB": "sql.OpenDB",
		"(method).connectPostgres": "pgx.Connect",
	}
	got, _ := pgxConnectSites(t, red)
	if len(got) != len(want) {
		t.Fatalf("RED: want %d planted violations found, got %d: %v", len(want), len(got), got)
	}
	for _, s := range got {
		if want[s.Fn] != s.Call {
			t.Errorf("RED: unexpected site %v (want %q)", s, want[s.Fn])
		}
	}

	_, bound = pgxConnectSites(t, map[string]string{"mention.go": `package dynamic
import (
	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/pgxlimits"
)
func connectPostgres(cfg *pgx.ConnConfig) { _ = pgxlimits.Apply; pgx.ConnectConfig(nil, cfg) }`})
	if bound {
		t.Error("RED: a bare mention of pgxlimits.Apply (not a call) must not count as applying the bound")
	}

	_, bound = pgxConnectSites(t, map[string]string{"nobound.go": `package dynamic
import "github.com/jackc/pgx/v5"
func connectPostgres(cfg *pgx.ConnConfig) { pgx.ConnectConfig(nil, cfg) }`})
	if bound {
		t.Error("RED: a connectPostgres that never calls pgxlimits.Apply must read as unbounded")
	}
}
