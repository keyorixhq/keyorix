// Package statemap generates the AT0 state map (SESSION-AT, docs/state-map/):
// every state store Keyorix has, and every entry point that can start a
// state transition. It is extraction tooling, not a runtime component --
// nothing here is imported by cmd/ or server/main.go.
//
// Design choice, stated up front: this is a pragmatic TEXT/AST extractor
// over known, single-location registration sites (one router file, one
// proto file, one scheduler-startup function, cobra command literals), not
// a whole-program go/ssa call graph. That is enough to make entry-point and
// DB-table ENUMERATION complete and mechanically checkable (see
// completeness_test.go), which is the property AT0(f) actually needs a
// guard for. It is NOT enough, by itself, to derive full per-entry-point
// write sets (AT0(c)) for all ~500 entry points -- that would need either a
// real call-graph tool (go/callgraph, cha or rta) or the dynamic
// faultstorage-recorder approach the brief also asks for. Named blind
// spots, so a future reader doesn't mistake "enumeration is complete" for
// "every write set is traced":
//   - REST route paths are the LOCAL path string at each chi .Get/.Post/...
//     call site, not the fully-mounted path (nested r.Route/r.Mount prefixes
//     are not composed in). Good enough for uniqueness/counting and for the
//     completeness guard's drift detection; not a literal curl-able URL.
//   - A route registered through a helper/wrapper function instead of a
//     literal chi method call on the router variable is invisible to the
//     regex-based REST extractor.
//   - CLI extraction finds cobra.Command LITERALS (&cobra.Command{Use: "..."})
//     reachable via AST walk of the target directories; a command built by
//     returning a *cobra.Command from a function taking non-literal
//     arguments would still be found (the walk matches the composite literal
//     itself, not how it's assigned), but a Use value built by string
//     concatenation/fmt.Sprintf rather than a plain string literal is not.
package statemap

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Entry describes one entry point: a way a state transition can start.
type Entry struct {
	Kind string // rest | grpc | cli | job
	ID   string // stable identifier used for diffing (method+path / service.Method / command path / job name)
	File string // relative to repo root
	Line int
}

// DBTable is one row of internal/storage/all_models.go's AllModels() --
// the codebase's own canonical, already-CI-guarded table list
// (TestAllModels_MatchesLiveMigratedTables). Reused here rather than
// re-deriving table existence from struct scanning, per this repo's
// "derive it, don't re-derive it" preference.
type DBTable struct {
	Model string
}

// FileWriteSite is a non-test call site that writes a file outside the
// securefiles atomic-write helpers (an AT4 guard candidate) or through them
// (informational -- these ARE going through the intended chokepoint).
type FileWriteSite struct {
	Func string // os.WriteFile | os.Create | securefiles.SecureWriteFile | ...
	File string
	Line int
}

var restCallRe = regexp.MustCompile(`\.(Get|Post|Put|Patch|Delete|Head|Options)\(\s*"([^"]*)"`)

// RESTRoutes extracts every chi route registration in server/http/router.go.
func RESTRoutes(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "server", "http", "router.go")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		return nil, err
	}
	var entries []Entry
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		for _, m := range restCallRe.FindAllStringSubmatch(line, -1) {
			method := strings.ToUpper(m[1])
			p := m[2]
			entries = append(entries, Entry{
				Kind: "rest",
				ID:   method + " " + p,
				File: filepath.Join("server", "http", "router.go"),
				Line: i + 1,
			})
		}
	}
	return dedupSortEntries(entries), nil
}

var protoRPCRe = regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\(`)
var protoServiceRe = regexp.MustCompile(`^\s*service\s+(\w+)\s*\{`)

// GRPCMethods extracts every "rpc Name(...)" line grouped under its
// enclosing "service X {" block in server/proto/keyorix.proto.
func GRPCMethods(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "server", "proto", "keyorix.proto")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		return nil, err
	}
	var entries []Entry
	currentService := ""
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if m := protoServiceRe.FindStringSubmatch(line); m != nil {
			currentService = m[1]
			continue
		}
		if m := protoRPCRe.FindStringSubmatch(line); m != nil {
			entries = append(entries, Entry{
				Kind: "grpc",
				ID:   currentService + "." + m[1],
				File: filepath.Join("server", "proto", "keyorix.proto"),
				Line: i + 1,
			})
		}
	}
	return dedupSortEntries(entries), nil
}

var schedulerCallRe = regexp.MustCompile(`runScheduler\(\s*ctx\s*,\s*"([^"]+)"`)

// ScheduledJobs extracts every runScheduler(ctx, "name", ...) call in
// server/main.go's startSchedulers.
func ScheduledJobs(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "server", "main.go")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		return nil, err
	}
	var entries []Entry
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if m := schedulerCallRe.FindStringSubmatch(line); m != nil {
			entries = append(entries, Entry{
				Kind: "job",
				ID:   m[1],
				File: filepath.Join("server", "main.go"),
				Line: i + 1,
			})
		}
	}
	return dedupSortEntries(entries), nil
}

// cliDirs are the cobra command trees in scope (server/admin per ADR-108's
// host-side admin split, and cmd/ / cli/ for the client-mode CLI). operator/
// is out of scope (MUST NOT EDIT list) and has its own command tree.
var cliDirs = []string{"server/admin", "cmd", "cli"}

// CLICommands walks cliDirs and finds every &cobra.Command{Use: "..."}
// composite literal via go/ast (not regex -- Long/Short fields commonly
// span multiple lines and a hand-rolled regex over that is fragile).
func CLICommands(repoRoot string) ([]Entry, error) {
	var entries []Entry
	for _, dir := range cliDirs {
		root := filepath.Join(repoRoot, dir)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			found, ferr := cobraCommandsInFile(p)
			if ferr != nil {
				return fmt.Errorf("%s: %w", p, ferr)
			}
			rel, rerr := filepath.Rel(repoRoot, p)
			if rerr != nil {
				rel = p
			}
			for _, f := range found {
				entries = append(entries, Entry{Kind: "cli", ID: f.use, File: rel, Line: f.line})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return dedupSortEntries(entries), nil
}

type cobraLit struct {
	use  string
	line int
}

func cobraCommandsInFile(path string) ([]cobraLit, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []cobraLit
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := cl.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Command" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "cobra" {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Use" {
				continue
			}
			if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				val := strings.Trim(lit.Value, "\"`")
				// Use strings often carry arg placeholders ("delete <id>"); keep
				// only the command token for a stable ID.
				val = strings.Fields(val)[0]
				out = append(out, cobraLit{use: val, line: fset.Position(cl.Pos()).Line})
			}
		}
		return true
	})
	return out, nil
}

func dedupSortEntries(in []Entry) []Entry {
	seen := map[string]bool{}
	var out []Entry
	for _, e := range in {
		key := e.Kind + "|" + e.ID + "|" + e.File + "|" + fmt.Sprint(e.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// AllEntries runs every extractor and returns the union.
func AllEntries(repoRoot string) ([]Entry, error) {
	var all []Entry
	rest, err := RESTRoutes(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("REST routes: %w", err)
	}
	all = append(all, rest...)
	grpc, err := GRPCMethods(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("gRPC methods: %w", err)
	}
	all = append(all, grpc...)
	jobs, err := ScheduledJobs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("scheduled jobs: %w", err)
	}
	all = append(all, jobs...)
	cli, err := CLICommands(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("CLI commands: %w", err)
	}
	all = append(all, cli...)
	return dedupSortEntries(all), nil
}

var allModelsRe = regexp.MustCompile(`&models\.(\w+)\{\}`)

// DBTables parses internal/storage/all_models.go's AllModels() function body
// for &models.X{} entries -- the codebase's own canonical table list,
// already drift-guarded by TestAllModels_MatchesLiveMigratedTables
// (internal/storage/all_models_test.go). Reused here, not re-derived.
func DBTables(repoRoot string) ([]DBTable, error) {
	path := filepath.Join(repoRoot, "internal", "storage", "all_models.go")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		return nil, err
	}
	var tables []DBTable
	for _, m := range allModelsRe.FindAllStringSubmatch(string(data), -1) {
		tables = append(tables, DBTable{Model: m[1]})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Model < tables[j].Model })
	return tables, nil
}

var fileWriteRe = regexp.MustCompile(`\b(os\.WriteFile|os\.Create|securefiles\.SecureWriteFile|securefiles\.SecureWriteFileSync|securefiles\.SecureCreateFile|securefiles\.SecureCreateFileSync|securefiles\.SecureCreateFileHandle)\(`)

// FileWriteSites walks the whole repo (excluding vendored/generated/test
// paths) for calls to a file-creating primitive, to support the AT4 guard
// "no direct os.WriteFile / os.Create outside the atomic-write helper".
func FileWriteSites(repoRoot string) ([]FileWriteSite, error) {
	var sites []FileWriteSite
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "operator": true, "web": true,
		"deploy": true, "vendor": true, "integrations": true,
	}
	err := filepath.Walk(repoRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(p) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(repoRoot, p)
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if m := fileWriteRe.FindStringSubmatch(line); m != nil {
				sites = append(sites, FileWriteSite{Func: m[1], File: rel, Line: i + 1})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, nil
}
