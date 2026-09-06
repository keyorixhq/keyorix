package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Finds every repo-defined interface with 2+ distinct concrete implementer
// types, across a set of module directories passed on argv.
//
// Usage: asymanalyzer [-json] [-root <repo-root>] <dir> [<dir> ...]
//
// -root sets the base all reported file paths are made relative to (so they
// match `git diff --name-only` output from the outer checkout, even when a
// separately-scanned module like operator/ lives in a subdirectory). Defaults
// to the first <dir> argument.

type implEntry struct {
	typeName string
	pkgPath  string
	file     string
	line     int
	col      int
	isPtr    bool
}

type ifaceInfo struct {
	name     string
	pkgPath  string
	file     string
	line     int
	col      int
	numMeths int
	impls    map[string]implEntry // key: pkgPath+"."+typeName (dedup ptr/value)
}

// JSON output schema. `id` is pkgPath+"."+name -- stable across runs as long
// as the interface keeps its package and name, which is exactly the identity
// a per-PR check needs (rename/move is itself worth flagging separately, not
// silently re-IDed).
type jsonMember struct {
	Type          string `json:"type"`
	Package       string `json:"package"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	IsPtrReceiver bool   `json:"is_ptr_receiver"`
}

type jsonFamily struct {
	ID         string       `json:"id"`
	Interface  string       `json:"interface"`
	Package    string       `json:"package"`
	File       string       `json:"file"`
	Line       int          `json:"line"`
	NumMethods int          `json:"num_methods"`
	Members    []jsonMember `json:"members"`
}

func main() {
	jsonOut := flag.Bool("json", false, "emit structured JSON instead of text")
	root := flag.String("root", "", "repo root to make file paths relative to (default: first scan dir)")
	flag.Parse()
	dirs := flag.Args()
	if len(dirs) < 1 {
		fmt.Fprintln(os.Stderr, "usage: asymanalyzer [-json] [-root <repo-root>] <dir> [<dir> ...]")
		os.Exit(1)
	}
	relBase := *root
	if relBase == "" {
		relBase = dirs[0]
	}
	absRelBase, err := filepath.Abs(relBase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve -root %q: %v\n", relBase, err)
		os.Exit(1)
	}

	var allFamilies []jsonFamily

	for _, dir := range dirs {
		cfg := &packages.Config{
			Dir:  dir,
			Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedImports | packages.NeedDeps | packages.NeedFiles,
			Env:  os.Environ(),
		}
		pkgs, err := packages.Load(cfg, "./...")
		if err != nil {
			fmt.Fprintf(os.Stderr, "load error for %s: %v\n", dir, err)
			os.Exit(1)
		}
		if n := packages.PrintErrors(pkgs); n > 0 {
			fmt.Fprintf(os.Stderr, "WARNING: %d package load errors for %s (see above), continuing with what loaded\n", n, dir)
		}

		seenPkg := map[string]bool{}
		var allPkgs []*packages.Package
		packages.Visit(pkgs, func(p *packages.Package) bool {
			if seenPkg[p.PkgPath] {
				return true
			}
			seenPkg[p.PkgPath] = true
			if isRepoPkg(p.PkgPath) {
				allPkgs = append(allPkgs, p)
			}
			return true
		}, nil)

		type ifaceWithType struct {
			info  *ifaceInfo
			iface *types.Interface
		}
		var withType []ifaceWithType
		type concreteType struct {
			name    string
			pkgPath string
			file    string
			line    int
			col     int
			named   *types.Named
		}
		var concreteTypes []concreteType

		for _, p := range allPkgs {
			if p.Types == nil {
				continue
			}
			scope := p.Types.Scope()
			for _, name := range scope.Names() {
				obj := scope.Lookup(name)
				tn, ok := obj.(*types.TypeName)
				if !ok {
					continue
				}
				named, ok := tn.Type().(*types.Named)
				if !ok {
					continue
				}
				pos := p.Fset.Position(obj.Pos())
				if iface, ok := named.Underlying().(*types.Interface); ok {
					if iface.NumMethods() == 0 {
						continue // skip empty interfaces (any, marker interfaces)
					}
					info := &ifaceInfo{
						name:     name,
						pkgPath:  p.PkgPath,
						file:     pos.Filename,
						line:     pos.Line,
						col:      pos.Column,
						numMeths: iface.NumMethods(),
						impls:    map[string]implEntry{},
					}
					withType = append(withType, ifaceWithType{info, iface})
				} else {
					concreteTypes = append(concreteTypes, concreteType{
						name:    name,
						pkgPath: p.PkgPath,
						file:    pos.Filename,
						line:    pos.Line,
						col:     pos.Column,
						named:   named,
					})
				}
			}
		}

		for _, iw := range withType {
			for _, ct := range concreteTypes {
				if ct.pkgPath+"."+ct.name == iw.info.pkgPath+"."+iw.info.name {
					continue
				}
				ptrType := types.NewPointer(ct.named)
				implementsVal := types.Implements(ct.named, iw.iface)
				implementsPtr := types.Implements(ptrType, iw.iface)
				if !implementsVal && !implementsPtr {
					continue
				}
				implKey := ct.pkgPath + "." + ct.name
				iw.info.impls[implKey] = implEntry{
					typeName: ct.name,
					pkgPath:  ct.pkgPath,
					file:     ct.file,
					line:     ct.line,
					col:      ct.col,
					isPtr:    !implementsVal && implementsPtr,
				}
			}
		}

		var keys []string
		infoByKey := map[string]*ifaceInfo{}
		for _, iw := range withType {
			k := iw.info.pkgPath + "." + iw.info.name
			infoByKey[k] = iw.info
			if len(iw.info.impls) >= 2 {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		for _, k := range keys {
			info := infoByKey[k]
			var implKeys []string
			for ik := range info.impls {
				implKeys = append(implKeys, ik)
			}
			sort.Strings(implKeys)

			fam := jsonFamily{
				ID:         k,
				Interface:  info.name,
				Package:    info.pkgPath,
				File:       relPath(absRelBase, info.file),
				Line:       info.line,
				NumMethods: info.numMeths,
			}
			for _, ik := range implKeys {
				e := info.impls[ik]
				fam.Members = append(fam.Members, jsonMember{
					Type:          e.typeName,
					Package:       e.pkgPath,
					File:          relPath(absRelBase, e.file),
					Line:          e.line,
					IsPtrReceiver: e.isPtr,
				})
			}
			allFamilies = append(allFamilies, fam)
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(allFamilies); err != nil {
			fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	for _, fam := range allFamilies {
		fmt.Printf("### INTERFACE %s (%s:%d) methods=%d impls=%d\n", fam.Interface, fam.File, fam.Line, fam.NumMethods, len(fam.Members))
		for _, m := range fam.Members {
			ptrNote := ""
			if m.IsPtrReceiver {
				ptrNote = " (ptr-receiver)"
			}
			fmt.Printf("  - %s.%s%s at %s:%d\n", m.Package, m.Type, ptrNote, m.File, m.Line)
		}
	}
}

// relPath makes file relative to base; falls back to the absolute path if it
// isn't under base (e.g. a type defined in a dependency, which shouldn't
// happen given isRepoPkg but fail soft rather than erroring the whole run).
func relPath(base, file string) string {
	rel, err := filepath.Rel(base, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return file
	}
	return rel
}

func isRepoPkg(pkgPath string) bool {
	return strings.HasPrefix(pkgPath, "github.com/keyorixhq/keyorix")
}
