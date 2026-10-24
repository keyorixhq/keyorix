package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// hotFileRule is the allowed shape of one central wiring file. A nil set means
// "any name"; an empty, non-nil set means "none at all".
type hotFileRule struct {
	path     string // repo-relative
	maxLines int    // 0: no ceiling
	funcs    []string
	types    []string
	vars     []string
	consts   []string
	// forbid reports a declaration or call that belongs in its own file.
	forbid func(fset *token.FileSet, f *ast.File) []string
}

// wiringHotFileRules: server/main.go, internal/config/config.go and
// internal/storage/factory.go are the files every feature used to edit (half of
// all merge-queue collisions in the week to 2026-10-19). They now keep ordered
// lists, and each feature is a new file plus one line in a list (CONTRIBUTING.md,
// "How to add a feature without touching shared wiring files").
//
// The sets below are a ratchet: they name what each file holds today. Growing one
// is a deliberate edit to this test, reviewed as such; shrinking one is always
// fine. The line ceilings leave room for list lines and Config field comments.
// factory.go has no ceiling: migrateDatabase still grows with every schema change
// (deliberately serialised by currentSchemaEpoch), so only its shape is held.
var wiringHotFileRules = []hotFileRule{
	{
		path:     "server/main.go",
		maxLines: 600,
		funcs:    []string{"main", "isAdminDispatch", "isVersionRequest"},
		types:    []string{},
		vars:     []string{"schedulerStarts", "coreWiringSteps", "bootRefusals"},
		consts:   []string{},
		forbid:   forbidInlineSchedulersAndWiring,
	},
	{
		// startSchedulers and initializeCoreService used to hold the job and
		// wiring blocks; they now only run the lists.
		path:   "server/schedulers.go",
		funcs:  []string{"startSchedulers", "legalHoldBlocks"},
		types:  []string{"schedulerStart"},
		vars:   []string{},
		consts: []string{},
		forbid: forbidInlineSchedulersAndWiring,
	},
	{
		path:   "server/boot_core.go",
		funcs:  []string{"initializeCoreService"},
		types:  []string{"coreWiring", "coreWiringStep"},
		vars:   []string{},
		consts: []string{},
		forbid: forbidInlineSchedulersAndWiring,
	},
	{
		path:     "internal/config/config.go",
		maxLines: 800,
		funcs: []string{
			"BoolPtr", "IntPtr", "parseDurationDefault", "resolveSecret", "Config.secretEnvNames",
			"Config.ValidateSecretSources", "Config.SecretFilePaths", "Config.EnforceSecretFilePermissions",
			"Config.keyMaterialSecretEnvNames", "ResolvedPath", "Load", "explicitSecurityKeys",
			"resolveConfigRelativePath", "expandEnvVars", "LoadConfig", "Config.Validate", "Save",
		},
		types:  []string{"Config"},
		vars:   []string{"SecretEnvVars", "envVarPattern", "configValidators"},
		consts: []string{"MaxSecretSizeHardCeiling", "appRootDir"},
		forbid: forbidInlineValidation,
	},
	{
		path:   "internal/storage/factory.go",
		types:  []string{"StorageFactory", "DefaultStorageFactory", "storageBackend", "schemaCheckRefusal"},
		forbid: forbidInlineBackends,
	},
}

// TestWiringHotFiles_StayThin fails when a function, type, variable, constant or
// a whole scheduler/wiring/validation/backend block is added directly to one of
// the three central wiring files instead of to its own file. It checks names and
// a few call/declaration shapes, not style; it does not look at what a list
// entry does or where in the list it sits.
func TestWiringHotFiles_StayThin(t *testing.T) {
	root := filepath.Join(srcpath.PkgDir(), "..")
	for _, r := range wiringHotFileRules {
		src, err := os.ReadFile(filepath.Join(root, r.path)) // #nosec G304 -- fixed repo files
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, r.path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		var problems []string
		if n := bytes.Count(src, []byte("\n")); r.maxLines > 0 && n > r.maxLines {
			problems = append(problems, "has "+strconv.Itoa(n)+" lines, ceiling "+strconv.Itoa(r.maxLines))
		}
		funcs, types, vars, consts := topLevelNames(f)
		problems = append(problems, notAllowed("func", funcs, r.funcs)...)
		problems = append(problems, notAllowed("type", types, r.types)...)
		problems = append(problems, notAllowed("var", vars, r.vars)...)
		problems = append(problems, notAllowed("const", consts, r.consts)...)
		if r.forbid != nil {
			problems = append(problems, r.forbid(fset, f)...)
		}
		for _, p := range problems {
			t.Errorf("%s %s: put it in its own file and add one line to the ordered list "+
				"(CONTRIBUTING.md, \"How to add a feature without touching shared wiring files\"); "+
				"if it really belongs here, extend wiringHotFileRules in this test", r.path, p)
		}
	}
}

func topLevelNames(f *ast.File) (funcs, types, vars, consts []string) {
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				name = recvTypeName(d.Recv.List[0].Type) + "." + name
			}
			funcs = append(funcs, name)
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					types = append(types, s.Name.Name)
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if d.Tok == token.CONST {
							consts = append(consts, n.Name)
						} else {
							vars = append(vars, n.Name)
						}
					}
				}
			}
		}
	}
	return funcs, types, vars, consts
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

func notAllowed(kind string, got, allowed []string) []string {
	if allowed == nil {
		return nil
	}
	var out []string
	for _, g := range got {
		if !slices.Contains(allowed, g) {
			out = append(out, "declares "+kind+" "+g)
		}
	}
	sort.Strings(out)
	return out
}

// forbidInlineSchedulersAndWiring: no background job is started and no core
// setting is applied in the file itself (main.go, schedulers.go, boot_core.go).
func forbidInlineSchedulersAndWiring(fset *token.FileSet, f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "runScheduler" || fn.Name == "runSchedulerAfter" || fn.Name == "lockedRun" {
				out = append(out, fset.Position(call.Pos()).String()+": starts a background job inline ("+fn.Name+")")
			}
		case *ast.SelectorExpr:
			if x, ok := fn.X.(*ast.Ident); ok && x.Name == "coreService" && strings.HasPrefix(fn.Sel.Name, "Set") {
				out = append(out, fset.Position(call.Pos()).String()+": wires a core setting inline (coreService."+fn.Sel.Name+")")
			}
		}
		return true
	})
	return out
}

// forbidInlineValidation: Validate stays the loop over configValidators.
func forbidInlineValidation(fset *token.FileSet, f *ast.File) []string {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "Validate" || fd.Recv == nil || fd.Body == nil {
			continue
		}
		if len(fd.Body.List) != 2 {
			return []string{fset.Position(fd.Pos()).String() + ": Validate has inline checks; add a validate<Section> function to configValidators instead"}
		}
		if rs, ok := fd.Body.List[0].(*ast.RangeStmt); !ok || !isIdent(rs.X, "configValidators") {
			return []string{fset.Position(fd.Pos()).String() + ": Validate no longer just ranges over configValidators"}
		}
	}
	return nil
}

// forbidInlineBackends: no backend constructor and no backend declaration in
// factory.go; CreateStorage selects from storageBackends.
func forbidInlineBackends(fset *token.FileSet, f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil && strings.HasPrefix(d.Name.Name, "create") {
				out = append(out, fset.Position(d.Pos()).String()+": declares backend constructor "+d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if vs, ok := s.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						if strings.HasSuffix(n.Name, "Backend") {
							out = append(out, fset.Position(n.Pos()).String()+": declares backend "+n.Name)
						}
					}
				}
			}
		}
	}
	return out
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
