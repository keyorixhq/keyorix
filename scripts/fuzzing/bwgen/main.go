//go:build ignore

// bwgen — bounded-work & round-trip fuzz target generator for Go libraries.
//
// It type-scans a set of packages (the keyorix module's own packages and any
// third-party package resolvable OFFLINE from the module cache) with
// golang.org/x/tools/go/packages, finds exported functions of the decoder /
// parser / validator shapes below, and emits:
//
//   - a bounded-work Fuzz target per matched function, using
//     internal/fuzzutil/boundedwork.Check to fail on super-linear (quadratic-or-
//     worse) time or memory growth, and
//   - a round-trip Fuzz target per Marshal/Unmarshal pair, asserting decode∘encode
//     is stable (idempotent) in addition to bounded-work.
//
// Matched function shapes (package-level funcs only; see note on methods):
//
//	A  func(IN) (T, error)      e.g. uuid.Parse, jwt.Parse, url.Parse
//	B  func(IN) T               e.g. blackfriday.Run (no error)
//	U  func(IN, any|*T) error   e.g. yaml.Unmarshal, toml.Unmarshal, cbor.Unmarshal
//	                            (the dominant decoder shape; IN is the FIRST param)
//
// where IN is one of []byte, string, io.Reader.
//
// Methods are REPORTED but not emitted: synthesising a receiver generically is
// not sound (no constructor is known), so a method target would not compile.
// This is a deliberate honest limitation, printed in the candidate report.
//
// Pure offline: packages.Load runs the type checker against the module cache; no
// network. Generated targets import third-party modules already in go.mod (direct
// or indirect — a test file may import an indirect dependency, which builds fine).
//
// NEVER auto-merge: a generated target that FIRES on its seeds means the library
// is super-linear on the pinned version; that is a FINDING, triaged and reported,
// not committed as a CI target (it would fail on its own seeds). Only targets that
// are GREEN on the pinned version are promoted to committed targets + targets.d.
package main

import (
	"flag"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

type inputKind int

const (
	inNone inputKind = iota
	inBytes
	inString
	inReader
)

func (k inputKind) expr(dataVar string) string {
	switch k {
	case inBytes:
		return dataVar
	case inString:
		return "string(" + dataVar + ")"
	case inReader:
		return "bytes.NewReader(" + dataVar + ")"
	}
	return ""
}

func classifyInput(t types.Type) inputKind {
	switch t.String() {
	case "[]byte":
		return inBytes
	case "string":
		return inString
	case "io.Reader":
		return inReader
	}
	return inNone
}

// target is one emittable bounded-work target.
type target struct {
	PkgPath  string // import path of the source package
	PkgName  string // package name
	Alias    string // import alias used in generated code
	Func     string // function name
	In       inputKind
	Family   rune // 'A' func(IN)(T,err)/func(IN)err, 'B' func(IN)T, 'U' func(IN,any)err
	Results  int  // number of result values (to emit the right blank count)
	IsMethod bool
	RecvType string // for reporting only
}

// rtpair is a Marshal/Unmarshal round-trip pair found in one package.
type rtpair struct {
	PkgPath, PkgName, Alias string
	Marshal, Unmarshal      string
}

func main() {
	out := flag.String("out", "", "directory to write generated *_bwgen_test.go files into (empty = report only)")
	pkgName := flag.String("pkgname", "boundedworksweep", "package name for generated files")
	pkgsFlag := flag.String("pkgs", "", "comma-separated import paths to scan")
	pkgsFile := flag.String("pkgs-file", "", "file with one import path per line (# comments allowed)")
	flag.Parse()

	var scan []string
	scan = append(scan, splitList(*pkgsFlag)...)
	if *pkgsFile != "" {
		raw, err := os.ReadFile(*pkgsFile)
		if err != nil {
			die("read pkgs-file: %v", err)
		}
		for _, ln := range strings.Split(string(raw), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			scan = append(scan, ln)
		}
	}
	if len(scan) == 0 {
		die("no packages to scan: pass -pkgs or -pkgs-file")
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
	}
	pkgs, err := packages.Load(cfg, scan...)
	if err != nil {
		die("packages.Load: %v", err)
	}

	var targets []target
	var pairs []rtpair
	var methods []target
	nErr := 0
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			nErr++
			fmt.Fprintf(os.Stderr, "LOAD ERROR %s: %v\n", p.PkgPath, p.Errors[0])
			continue
		}
		if p.Types == nil {
			continue
		}
		alias := aliasFor(p.PkgPath)
		scope := p.Types.Scope()
		var marshal, unmarshal string
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() {
				continue
			}
			fn, ok := obj.(*types.Func)
			if !ok {
				// Named type: scan its exported methods for the report.
				if tn, ok := obj.(*types.TypeName); ok {
					if named, ok := tn.Type().(*types.Named); ok {
						for i := 0; i < named.NumMethods(); i++ {
							m := named.Method(i)
							if !m.Exported() {
								continue
							}
							if t, ok := matchFunc(m, p, alias); ok {
								t.IsMethod = true
								t.RecvType = name
								methods = append(methods, t)
							}
						}
					}
				}
				continue
			}
			sig := fn.Type().(*types.Signature)
			if sig.Recv() != nil {
				continue
			}
			// Round-trip pair detection.
			if name == "Marshal" && isMarshal(sig) {
				marshal = name
			}
			if name == "Unmarshal" && isUnmarshal(sig) {
				unmarshal = name
			}
			if t, ok := matchFunc(fn, p, alias); ok {
				targets = append(targets, t)
			}
		}
		if marshal != "" && unmarshal != "" {
			pairs = append(pairs, rtpair{p.PkgPath, p.Types.Name(), alias, marshal, unmarshal})
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].PkgPath != targets[j].PkgPath {
			return targets[i].PkgPath < targets[j].PkgPath
		}
		return targets[i].Func < targets[j].Func
	})
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].PkgPath < pairs[j].PkgPath })

	// ---- report ----
	fmt.Printf("== bwgen: %d bounded-work function targets, %d round-trip pairs, %d methods (reported only) ==\n",
		len(targets), len(pairs), len(methods))
	for _, t := range targets {
		fmt.Printf("  [%c] %-40s %s(%s)\n", t.Family, t.PkgPath, t.Func, inName(t.In))
	}
	for _, p := range pairs {
		fmt.Printf("  [RT] %-40s %s/%s\n", p.PkgPath, p.Marshal, p.Unmarshal)
	}
	for _, m := range methods {
		fmt.Printf("  [m] %-40s (%s).%s(%s)  — reported only (no receiver constructor)\n",
			m.PkgPath, m.RecvType, m.Func, inName(m.In))
	}

	if *out == "" {
		return
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die("mkdir out: %v", err)
	}
	// Group targets + pairs by source package → one file each.
	byPkg := map[string][]target{}
	for _, t := range targets {
		byPkg[t.PkgPath] = append(byPkg[t.PkgPath], t)
	}
	pairByPkg := map[string]rtpair{}
	for _, p := range pairs {
		pairByPkg[p.PkgPath] = p
	}
	allPkgs := map[string]bool{}
	for k := range byPkg {
		allPkgs[k] = true
	}
	for k := range pairByPkg {
		allPkgs[k] = true
	}
	var keys []string
	for k := range allPkgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	nFiles := 0
	for _, pkgPath := range keys {
		code := emitFile(*pkgName, pkgPath, byPkg[pkgPath], pairByPkg)
		fname := "zz_" + aliasFor(pkgPath) + "_bwgen_test.go"
		if err := os.WriteFile(filepath.Join(*out, fname), []byte(code), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", fname, err)
			continue
		}
		nFiles++
		fmt.Printf("wrote %s\n", fname)
	}
	fmt.Printf("== emitted %d files into %s ==\n", nFiles, *out)
}

// blockedName excludes functions that must never be driven by a fuzzer:
// network side-effects (http.Get/Head/Post) and panic-by-design constructors
// (Must*), which would record false crashes rather than real findings.
func blockedName(pkgPath, name string) bool {
	if strings.HasPrefix(name, "Must") {
		return true
	}
	switch name {
	case "Get", "Head", "Post", "PostForm": // net/http network calls
		return true
	case "NewEncoding", "NewReplacer": // panic-by-contract constructors, not parsers
		return true
	}
	// User builds a *Userinfo, not a parser; NewRequest etc. do IO.
	if pkgPath == "net/url" && name == "User" {
		return true
	}
	return false
}

func matchFunc(fn *types.Func, p *packages.Package, alias string) (target, bool) {
	if blockedName(p.PkgPath, fn.Name()) {
		return target{}, false
	}
	sig := fn.Type().(*types.Signature)
	params := sig.Params()
	results := sig.Results()
	t := target{PkgPath: p.PkgPath, PkgName: p.Types.Name(), Alias: alias, Func: fn.Name()}

	lastErr := results.Len() >= 1 && results.At(results.Len()-1).Type().String() == "error"

	// Family U: func(IN, any|*T) error
	if params.Len() == 2 && results.Len() == 1 && lastErr {
		in := classifyInput(params.At(0).Type())
		if in != inNone && isSinkArg(params.At(1).Type()) {
			t.In, t.Family, t.Results = in, 'U', 1
			return t, true
		}
	}
	// Family A/B: single input param.
	if params.Len() == 1 {
		in := classifyInput(params.At(0).Type())
		if in == inNone {
			return target{}, false
		}
		switch {
		case results.Len() == 2 && lastErr:
			t.In, t.Family, t.Results = in, 'A', 2
			return t, true
		case results.Len() == 1 && !lastErr:
			t.In, t.Family, t.Results = in, 'B', 1
			return t, true
		case results.Len() == 1 && lastErr:
			// func(IN) error — a validator. Discard the error (family A, 1 result).
			t.In, t.Family, t.Results = in, 'A', 1
			return t, true
		}
	}
	return target{}, false
}

// isSinkArg reports whether t is a decode destination: interface{}/any or a pointer.
func isSinkArg(t types.Type) bool {
	if iface, ok := t.Underlying().(*types.Interface); ok {
		return iface.NumMethods() == 0 // empty interface = any
	}
	_, ok := t.Underlying().(*types.Pointer)
	return ok
}

func isMarshal(sig *types.Signature) bool {
	// func(any) ([]byte, error)
	return sig.Params().Len() == 1 && sig.Results().Len() == 2 &&
		sig.Results().At(0).Type().String() == "[]byte" &&
		sig.Results().At(1).Type().String() == "error"
}

func isUnmarshal(sig *types.Signature) bool {
	// func([]byte, any) error
	return sig.Params().Len() == 2 && sig.Results().Len() == 1 &&
		classifyInput(sig.Params().At(0).Type()) == inBytes &&
		isSinkArg(sig.Params().At(1).Type()) &&
		sig.Results().At(0).Type().String() == "error"
}

func emitFile(pkgName, pkgPath string, ts []target, pairByPkg map[string]rtpair) string {
	var b strings.Builder
	alias := aliasFor(pkgPath)
	fmt.Fprintf(&b, "// Code generated by scripts/fuzzing/bwgen. DO NOT EDIT.\n")
	fmt.Fprintf(&b, "// Bounded-work (super-linear time/memory) + round-trip targets for %s.\n", pkgPath)
	fmt.Fprintf(&b, "// A target that FIRES on its seeds is a FINDING (triaged in the bw1 report),\n")
	fmt.Fprintf(&b, "// not evidence the library is safe — see scripts/fuzzing/bwgen/main.go.\n\n")
	_, hasRT := pairByPkg[pkgPath]
	needBytes := hasRT
	for _, t := range ts {
		if t.In == inReader {
			needBytes = true
		}
	}
	fmt.Fprintf(&b, "package %s\n\n", pkgName)
	fmt.Fprintf(&b, "import (\n")
	if needBytes {
		fmt.Fprintf(&b, "\t\"bytes\"\n")
	}
	fmt.Fprintf(&b, "\t\"testing\"\n\n")
	fmt.Fprintf(&b, "\t\"github.com/keyorixhq/keyorix/internal/fuzzutil/boundedwork\"\n\n")
	fmt.Fprintf(&b, "\t%s %q\n)\n\n", alias, pkgPath)

	for _, t := range ts {
		emitBoundedWork(&b, t)
	}
	if rt, ok := pairByPkg[pkgPath]; ok {
		emitRoundTrip(&b, rt)
	}
	return b.String()
}

func emitBoundedWork(b *strings.Builder, t target) {
	fn := fmt.Sprintf("Fuzz_%s_%s_BoundedWork", t.Alias, t.Func)
	call := callExpr(t, "in")
	fmt.Fprintf(b, "func %s(f *testing.F) {\n", fn)
	for _, s := range seeds() {
		fmt.Fprintf(b, "\tf.Add([]byte(%q))\n", s)
	}
	fmt.Fprintf(b, "\tf.Fuzz(func(t *testing.T, data []byte) {\n")
	fmt.Fprintf(b, "\t\tif len(data) == 0 {\n\t\t\treturn\n\t\t}\n")
	fmt.Fprintf(b, "\t\tboundedwork.Check(t.Fatalf, %q, data, boundedwork.ScaleRepeat(512),\n", t.PkgName+"."+t.Func)
	// recover(): a panic on hostile input is out of scope for the bounded-work
	// oracle (never-panic harnesses cover crashes). Recovering keeps one panicking
	// seed from aborting the whole sweep binary, and lets the time/memory curve
	// still be measured on the inputs that do not panic.
	fmt.Fprintf(b, "\t\t\tfunc(in []byte) { defer func() { _ = recover() }(); %s }, boundedwork.Config{})\n", call)
	fmt.Fprintf(b, "\t})\n}\n\n")
}

// callExpr renders the discard-result call for the target family.
func callExpr(t target, dataVar string) string {
	arg := t.In.expr(dataVar)
	switch t.Family {
	case 'A', 'B':
		blanks := strings.TrimSuffix(strings.Repeat("_, ", t.Results), ", ")
		return fmt.Sprintf("%s = %s.%s(%s)", blanks, t.Alias, t.Func, arg)
	case 'U':
		return fmt.Sprintf("var v any; _ = %s.%s(%s, &v)", t.Alias, t.Func, arg)
	}
	return ""
}

func emitRoundTrip(b *strings.Builder, rt rtpair) {
	fmt.Fprintf(b, "func Fuzz_%s_RoundTrip(f *testing.F) {\n", rt.Alias)
	for _, s := range seeds() {
		fmt.Fprintf(b, "\tf.Add([]byte(%q))\n", s)
	}
	fmt.Fprintf(b, "\tf.Fuzz(func(t *testing.T, data []byte) {\n")
	fmt.Fprintf(b, "\t\tif len(data) == 0 {\n\t\t\treturn\n\t\t}\n")
	// t.Fatalf uses runtime.Goexit (not panic), so this recover swallows only a
	// library panic, never the ROUND-TRIP failure signal.
	fmt.Fprintf(b, "\t\tdefer func() { _ = recover() }()\n")
	fmt.Fprintf(b, "\t\t// Bounded-work on decode.\n")
	fmt.Fprintf(b, "\t\tboundedwork.Check(t.Fatalf, %q, data, boundedwork.ScaleRepeat(512),\n", rt.PkgName+".Unmarshal")
	fmt.Fprintf(b, "\t\t\tfunc(in []byte) { defer func() { _ = recover() }(); var v any; _ = %s.Unmarshal(in, &v) }, boundedwork.Config{})\n", rt.Alias)
	fmt.Fprintf(b, "\t\t// Decode∘encode stability (idempotence) — a correctness oracle.\n")
	fmt.Fprintf(b, "\t\tvar v any\n")
	fmt.Fprintf(b, "\t\tif %s.Unmarshal(data, &v) != nil {\n\t\t\treturn\n\t\t}\n", rt.Alias)
	fmt.Fprintf(b, "\t\tb1, err := %s.Marshal(v)\n\t\tif err != nil {\n\t\t\treturn\n\t\t}\n", rt.Alias)
	fmt.Fprintf(b, "\t\tvar v2 any\n")
	fmt.Fprintf(b, "\t\tif %s.Unmarshal(b1, &v2) != nil {\n\t\t\treturn\n\t\t}\n", rt.Alias)
	fmt.Fprintf(b, "\t\tb2, err := %s.Marshal(v2)\n\t\tif err != nil {\n\t\t\treturn\n\t\t}\n", rt.Alias)
	fmt.Fprintf(b, "\t\tif !bytes.Equal(b1, b2) {\n")
	fmt.Fprintf(b, "\t\t\tt.Fatalf(%q, len(b1), len(b2))\n", "ROUND-TRIP: decode∘encode not stable (b1=%d b2=%d bytes)")
	fmt.Fprintf(b, "\t\t}\n\t})\n}\n\n")
}

// seeds are parser-stressing inputs that naturally scale into super-linear
// regimes when repeated by the oracle's ScaleRepeat: a duplicate-key line, a
// nested-open run, a deep bracket, repeated separators, plus trivial values.
func seeds() []string {
	return []string{
		"a: 1\n",                 // YAML duplicate-key line (the calibration shape)
		"{\"a\":1}",              // JSON object
		"a = 1\n",                // TOML line
		"[[[[[[[[",               // nested open brackets
		"{{{{{{{{",               // nested open braces
		",,,,,,,,",               // repeated separators
		"0",                      // trivial scalar
		"aaaaaaaa",               // repeated bytes
	}
}

func aliasFor(path string) string {
	// Last two segments, sanitised, to disambiguate yaml.v2 vs yaml.v3 etc.
	segs := strings.Split(path, "/")
	n := len(segs)
	pick := segs[n-1]
	if n >= 2 {
		pick = segs[n-2] + "_" + segs[n-1]
	}
	var sb strings.Builder
	sb.WriteString("lib_")
	for _, r := range pick {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

func inName(k inputKind) string {
	switch k {
	case inBytes:
		return "[]byte"
	case inString:
		return "string"
	case inReader:
		return "io.Reader"
	}
	return "?"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "bwgen: "+format+"\n", args...)
	os.Exit(1)
}
