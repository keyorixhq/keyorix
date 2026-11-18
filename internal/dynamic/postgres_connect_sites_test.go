package dynamic

// postgres_connect_sites_test.go — every pgx connection internal/dynamic opens
// toward an admin_dsn host must be built by connectPostgres, because that is the
// one place pgxlimits.Apply is called (see
// postgres_max_body_len_test.go for why the bound exists). A second, direct
// pgx.Connect* call in this package would silently reintroduce the unbounded
// server-claimed allocation, and no behavioural test of the existing engines
// would notice.
//
// Recognised connect idioms (a call through an import of github.com/jackc/pgx/v5,
// .../pgconn, .../pgxpool or .../stdlib whose name is in pgxConnectFuncs, plus
// database/sql.Open with the literal driver name "pgx"). That list was derived
// from those four packages' exported constructors that dial a server, and is
// what a reviewer should check when pgx grows a new one.
//
// What this does NOT cover: other packages (internal/storage, internal/auditverify
// and internal/rotation open their own pgx or database/sql connections against
// operator-trusted databases and are out of scope here), a connection obtained by
// a call this package does not make itself (a driver registered elsewhere and
// opened via a name other than the literal "pgx"), and any connect reached through
// reflection or a function value assigned from a non-literal.

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
	"github.com/jackc/pgx/v5":         true,
	"github.com/jackc/pgx/v5/pgconn":  true,
	"github.com/jackc/pgx/v5/pgxpool": true,
	"github.com/jackc/pgx/v5/stdlib":  true,
}

const pgxlimitsPath = "github.com/keyorixhq/keyorix/internal/pgxlimits"

var pgxConnectFuncs = map[string]bool{
	"Connect": true, "ConnectConfig": true, "ConnectWithOptions": true,
	"New": true, "NewWithConfig": true, "OpenDB": true, "Open": true,
}

type pgxSite struct{ Fn, Call string }

// pgxConnectSites lists every recognised pgx connect call in src (file name ->
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
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !pgxImportPaths[path] && path != "database/sql" && path != pgxlimitsPath {
				continue
			}
			n := path[strings.LastIndex(path, "/")+1:]
			if n == "v5" { // github.com/jackc/pgx/v5 declares package pgx
				n = "pgx"
			}
			if imp.Name != nil {
				n = imp.Name.Name
			}
			local[n] = path
		}
		for _, d := range f.Decls {
			fn := "<package-level>"
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					se, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := se.X.(*ast.Ident)
					if !ok {
						return true
					}
					path := local[id.Name]
					if path == pgxlimitsPath && se.Sel.Name == "Apply" && fn == "connectPostgres" {
						setsBound = true
					}
					if pgxImportPaths[path] && pgxConnectFuncs[se.Sel.Name] {
						sites = append(sites, pgxSite{fn, id.Name + "." + se.Sel.Name})
					}
					if path == "database/sql" && se.Sel.Name == "Open" && len(x.Args) > 0 {
						if lit, ok := x.Args[0].(*ast.BasicLit); ok && strings.Trim(lit.Value, "\"`") == "pgx" {
							sites = append(sites, pgxSite{fn, "sql.Open(\"pgx\")"})
						}
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
			t.Errorf("%s is called from %s: pgx connections toward an admin_dsn host must be built by connectPostgres, "+
				"which applies postgresMaxProtocolMessageBodyLen", s.Call, s.Fn)
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
	}
	want := map[string]string{"other": "pgx.Connect", "aliased": "pg.ConnectConfig", "<package-level>": "pgxpool.New", "viaSQL": `sql.Open("pgx")`}
	got, _ := pgxConnectSites(t, red)
	if len(got) != len(want) {
		t.Fatalf("RED: want %d planted violations found, got %v", len(want), got)
	}
	for _, s := range got {
		if want[s.Fn] != s.Call {
			t.Errorf("RED: unexpected site %v", s)
		}
	}

	_, bound = pgxConnectSites(t, map[string]string{"nobound.go": `package dynamic
import "github.com/jackc/pgx/v5"
func connectPostgres(cfg *pgx.ConnConfig) { pgx.ConnectConfig(nil, cfg) }`})
	if bound {
		t.Error("RED: a connectPostgres that never calls pgxlimits.Apply must read as unbounded")
	}
}
