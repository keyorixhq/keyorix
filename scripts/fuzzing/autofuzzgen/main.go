//go:build ignore

// autofuzzgen — a fuzz-harness lead generator for the keyorix module.
//
// Two modes:
//
//	-tuples <file>   SAST-GUIDED (preferred). Consume a source->sink tuple list emitted by the
//	                 FuzzHarnessTargets CodeQL query (.github/codeql/go-queries) and emit one
//	                 harness SKELETON per tuple, with the invariant family chosen by the sink
//	                 kind. A skeleton is a STARTING POINT: the generator picks the place (a
//	                 function static data-flow says untrusted input actually reaches) and the
//	                 invariant family; the engineer supplies the oracle specifics and red-proofs
//	                 it before it is committed and gets a targets.conf row. Each skeleton carries
//	                 an auditable header naming the source->sink path it was chosen for.
//
//	-root <dir>      SIGNATURE-SCAN (fallback, the original behaviour). Pure syntactic AST walk:
//	                 an exported func whose every parameter is a Go-native-fuzzing type with >=1
//	                 string/[]byte, not already harnessed -> a never-panic FuzzAuto_<name>. A weak
//	                 selector (fuzzes exported leaves regardless of reachability); kept for quick
//	                 sweeps where no taint list is available.
//
// Pure stdlib, no module build required. NEVER auto-merge generated harnesses: they are leads,
// reviewed + red-proofed like any hand-written harness (see README.md).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var allowedScalar = map[string]bool{
	"string": true, "bool": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"byte": true, "rune": true, "float32": true, "float64": true,
}

func zeroLit(t string) string {
	switch t {
	case "string":
		return `""`
	case "[]byte":
		return "[]byte(nil)"
	case "bool":
		return "false"
	case "float32", "float64":
		return "0"
	default:
		return "0"
	}
}

func fuzzType(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.Ident:
		if allowedScalar[v.Name] {
			return v.Name, true
		}
	case *ast.ArrayType:
		if v.Len == nil {
			if id, ok := v.Elt.(*ast.Ident); ok && id.Name == "byte" {
				return "[]byte", true
			}
		}
	}
	return "", false
}

func main() {
	root := flag.String("root", "", "signature-scan mode: directory to scan")
	tuples := flag.String("tuples", "", "SAST-guided mode: JSON tuple list from the FuzzHarnessTargets CodeQL query")
	emit := flag.Bool("emit", false, "write generated files (default: report only)")
	out := flag.String("out", "", "SAST-guided mode: directory to write skeletons into (default: report only)")
	maxParams := flag.Int("maxparams", 6, "signature-scan: skip funcs with more than this many params")
	skip := flag.String("skip", "", "signature-scan: comma-separated pkg.Name substrings to exclude")
	flag.Parse()

	switch {
	case *tuples != "":
		runTuples(*tuples, *out)
	case *root != "":
		runSignatureScan(*root, *emit, *maxParams, *skip)
	default:
		fmt.Fprintln(os.Stderr, "autofuzzgen: pass -tuples <file> (SAST-guided) or -root <dir> (signature-scan)")
		os.Exit(2)
	}
}

// ================= SAST-guided mode =================

// Tuple is one source->sink lead from the FuzzHarnessTargets query, projected from the
// query's JSON result rows (codeql bqrs decode --format=json).
type Tuple struct {
	Package    string `json:"package"`    // import path
	Dir        string `json:"dir"`        // module-relative dir, e.g. internal/core
	Func       string `json:"func"`       // function to fuzz (the sink's enclosing exported entry)
	SinkKind   string `json:"sinkKind"`   // parser | alloc | authz | crypto | format
	EntryParam string `json:"entryParam"` // the untrusted parameter name/type, if known
	Source     string `json:"source"`     // human-readable source location (the "why")
	Sink       string `json:"sink"`       // human-readable sink location (the "why")
}

var invariantFamily = map[string]string{
	"parser": "bounded-work + never-panic (decode time/alloc bounded vs input size)",
	"alloc":  "bounded-work (allocation bounded by, and validated against, the input)",
	"authz":  "fail-closed differential (an unauthorized principal must be denied)",
	"crypto": "tamper / round-trip / key-commitment (reuse the FuzzAEADTamperRoundTrip shape)",
	"format": "injection (no control char, formula prefix = + - @, or forged audit/log line)",
}

func runTuples(path, outDir string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read tuples:", err)
		os.Exit(1)
	}
	var ts []Tuple
	if err := json.Unmarshal(raw, &ts); err != nil {
		fmt.Fprintln(os.Stderr, "parse tuples JSON:", err)
		os.Exit(1)
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].SinkKind != ts[j].SinkKind {
			return ts[i].SinkKind < ts[j].SinkKind
		}
		return ts[i].Func < ts[j].Func
	})

	fmt.Printf("== %d SAST-guided harness leads (source->sink, by sink kind) ==\n", len(ts))
	for _, t := range ts {
		fam := invariantFamily[t.SinkKind]
		if fam == "" {
			fam = "never-panic (unknown sink kind - baseline only)"
		}
		fmt.Printf("[%-6s] %-40s %s\n           why: %s  ->  %s\n           oracle: %s\n",
			t.SinkKind, t.Dir+"."+t.Func, t.EntryParam, t.Source, t.Sink, fam)
	}

	if outDir == "" {
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir out:", err)
		os.Exit(1)
	}
	for i, t := range ts {
		name := fmt.Sprintf("autotarget_%s_%s.txt", t.SinkKind, safeIdent(t.Func))
		if err := os.WriteFile(filepath.Join(outDir, name), []byte(skeleton(t)), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write", name, err)
			continue
		}
		fmt.Printf("wrote %s (%d/%d)\n", name, i+1, len(ts))
	}
	fmt.Println("\nNOTE: skeletons are emitted as .txt on purpose - review, fill the oracle, rename to")
	fmt.Println("<pkg>_<name>_fuzz_test.go in the target package, red-proof, then add a targets.conf row.")
}

func safeIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

func skeleton(t Tuple) string {
	var b strings.Builder
	fam := invariantFamily[t.SinkKind]
	if fam == "" {
		fam = "never-panic baseline (sink kind not recognised)"
	}
	fmt.Fprintf(&b, "// AUTO-TARGETED by autofuzzgen (SAST-guided). NOT a finished harness - a reviewed,\n")
	fmt.Fprintf(&b, "// red-proofed starting point. Fill the oracle, rename to a *_fuzz_test.go in package,\n")
	fmt.Fprintf(&b, "// then add a targets.conf row. Never auto-merge.\n//\n")
	fmt.Fprintf(&b, "// WHY (static data-flow, %s sink):\n//   source: %s\n//   sink:   %s\n//   fuzz:   %s.%s(%s)\n//\n",
		t.SinkKind, t.Source, t.Sink, t.Dir, t.Func, t.EntryParam)
	fmt.Fprintf(&b, "// INVARIANT FAMILY: %s\n\n", fam)
	pkg := t.Package
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	if pkg == "" {
		pkg = "PACKAGE"
	}
	fmt.Fprintf(&b, "package %s\n\nimport (\n\t\"testing\"\n)\n\n", pkg)
	fmt.Fprintf(&b, "func FuzzTarget_%s(f *testing.F) {\n", safeIdent(t.Func))
	fmt.Fprintf(&b, "\tf.Add([]byte(nil)) // TODO: seed with realistic %s inputs for this source\n", t.SinkKind)
	fmt.Fprintf(&b, "\tf.Fuzz(func(t *testing.T, data []byte) {\n")
	fmt.Fprintf(&b, "\t\t// TODO: build the call to %s from `data` (entry param: %s).\n", t.Func, t.EntryParam)
	b.WriteString(sinkKindBody(t.SinkKind))
	fmt.Fprintf(&b, "\t})\n}\n")
	return b.String()
}

func sinkKindBody(kind string) string {
	switch kind {
	case "parser":
		return "\t\t// PARSER sink -> bounded-work + never-panic. Assert: no panic; decode time and\n" +
			"\t\t// allocation stay bounded relative to len(data) (no decompression/nesting bomb). A value\n" +
			"\t\t// unmarshalled from data then used as a size/bound must survive its own validation.\n" +
			"\t\t// Assert only the bounded/never-panic direction (never \"must decode\").\n"
	case "alloc":
		return "\t\t// ALLOC/SIZE-MULTIPLY sink -> bounded-work. The allocated size must be bounded by, and\n" +
			"\t\t// validated against, the input: an unmarshalled length used as make([]T, n) must be\n" +
			"\t\t// range-checked first. Assert the allocation stays proportional to len(data).\n"
	case "authz":
		return "\t\t// AUTHZ sink -> fail-closed differential. Reuse the allow/deny/OTHER classifier from the\n" +
			"\t\t// parity harnesses: a principal the model says may NOT act must be denied. Assert only\n" +
			"\t\t// the deny direction (never \"authorized => must succeed\").\n"
	case "crypto":
		return "\t\t// CRYPTO sink -> tamper / round-trip / key-commitment. Reuse the FuzzAEADTamperRoundTrip\n" +
			"\t\t// shape: a tampered ciphertext/tag must never open; a round-trip must return the exact\n" +
			"\t\t// plaintext; a wrong key must never open. Assert only the reject/equality directions.\n"
	case "format":
		return "\t\t// FORMAT/TEMPLATE/LOG sink -> injection. No field lifted from data may smuggle a control\n" +
			"\t\t// char, a spreadsheet formula prefix (= + - @), or a forged audit/log line - the\n" +
			"\t\t// sanitizeAuditText property. Assert the sanitised output is free of those.\n"
	default:
		return "\t\t// (baseline) Assert the call does not panic on hostile input.\n"
	}
}

// ================= signature-scan mode (original .scratch/autofuzzgen.go behaviour) =================

type cand struct {
	pkg, dir, name string
	params         []string
	nres           int
}

func runSignatureScan(root string, emit bool, maxParams int, skip string) {
	var skips []string
	for _, s := range strings.Split(skip, ",") {
		if s = strings.TrimSpace(s); s != "" {
			skips = append(skips, s)
		}
	}
	skipped := func(key string) bool {
		for _, sub := range skips {
			if strings.Contains(key, sub) {
				return true
			}
		}
		return false
	}

	fset := token.NewFileSet()
	harnessed := map[string]map[string]bool{}
	var cands []cand

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_fuzz_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		dir := filepath.Dir(path)
		if harnessed[dir] == nil {
			harnessed[dir] = map[string]bool{}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok {
				if id, ok := ce.Fun.(*ast.Ident); ok {
					harnessed[dir][id.Name] = true
				}
			}
			return true
		})
		return nil
	})

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		dir := filepath.Dir(path)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !fd.Name.IsExported() || fd.Type.Params == nil {
				continue
			}
			if harnessed[dir][fd.Name.Name] {
				continue
			}
			var ptypes []string
			hasBytes, allFuzz := false, true
			for _, field := range fd.Type.Params.List {
				ft, ok := fuzzType(field.Type)
				n := len(field.Names)
				if n == 0 {
					n = 1
				}
				if !ok {
					allFuzz = false
					break
				}
				if ft == "string" || ft == "[]byte" {
					hasBytes = true
				}
				for i := 0; i < n; i++ {
					ptypes = append(ptypes, ft)
				}
			}
			if !allFuzz || !hasBytes || len(ptypes) == 0 || len(ptypes) > maxParams {
				continue
			}
			nres := 0
			if fd.Type.Results != nil {
				for _, r := range fd.Type.Results.List {
					if len(r.Names) == 0 {
						nres++
					} else {
						nres += len(r.Names)
					}
				}
			}
			if skipped(f.Name.Name + "." + fd.Name.Name) {
				continue
			}
			cands = append(cands, cand{pkg: f.Name.Name, dir: dir, name: fd.Name.Name, params: ptypes, nres: nres})
		}
		return nil
	})

	sort.Slice(cands, func(i, j int) bool {
		if cands[i].dir != cands[j].dir {
			return cands[i].dir < cands[j].dir
		}
		return cands[i].name < cands[j].name
	})

	fmt.Printf("== %d auto-fuzzable candidates (all params fuzzer-typed, >=1 string/[]byte, not already harnessed) ==\n", len(cands))
	for _, c := range cands {
		fmt.Printf("%-28s %s(%s) -> %d results\n", c.pkg, c.name, strings.Join(c.params, ", "), c.nres)
	}
	if !emit {
		return
	}
	byDir := map[string][]cand{}
	for _, c := range cands {
		byDir[c.dir] = append(byDir[c.dir], c)
	}
	for dir, cs := range byDir {
		var b strings.Builder
		fmt.Fprintf(&b, "package %s\n\nimport (\n\t\"testing\"\n\n\t\"github.com/keyorixhq/keyorix/internal/fuzzutil\"\n)\n\n", cs[0].pkg)
		fmt.Fprintf(&b, "// Code generated by autofuzzgen. DO NOT EDIT by hand for invariants;\n// these are never-panic baselines - promote interesting ones to real harnesses.\n\n")
		for _, c := range cs {
			args := make([]string, len(c.params))
			seeds := make([]string, len(c.params))
			for i, p := range c.params {
				args[i] = fmt.Sprintf("a%d %s", i, p)
				seeds[i] = zeroLit(p)
			}
			callArgs := make([]string, len(c.params))
			for i := range c.params {
				callArgs[i] = fmt.Sprintf("a%d", i)
			}
			lhs := ""
			if c.nres == 1 {
				lhs = "_ = "
			} else if c.nres > 1 {
				lhs = strings.TrimSuffix(strings.Repeat("_, ", c.nres), ", ") + " = "
			}
			fmt.Fprintf(&b, "func FuzzAuto_%s(f *testing.F) {\n", c.name)
			fmt.Fprintf(&b, "\tf.Add(%s)\n", strings.Join(seeds, ", "))
			fmt.Fprintf(&b, "\tf.Fuzz(func(t *testing.T, %s) {\n", strings.Join(args, ", "))
			fmt.Fprintf(&b, "\t\tfuzzutil.Guard(t.Fatalf, %q, func() {\n\t\t\t%s%s(%s)\n\t\t})\n", c.pkg+"."+c.name, lhs, c.name, strings.Join(callArgs, ", "))
			fmt.Fprintf(&b, "\t})\n}\n\n")
		}
		outf := filepath.Join(dir, "autofuzz_test.go")
		if err := os.WriteFile(outf, []byte(b.String()), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write", outf, err)
			continue
		}
		fmt.Println("wrote", outf, "(", len(cs), "targets )")
	}
}
