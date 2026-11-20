//go:build ignore

// apigen — exported-surface API inventory generator for Go libraries.
//
// Produces a JSON inventory of every exported function and method in a Go
// package (or package path), annotating each symbol with:
//
//   - full signature
//   - receiver type (empty for package-level functions)
//   - parameter classifications: untrusted-bytes / structured / handle / config
//   - whether the symbol can panic by contract (Must* prefix or doc comment)
//   - whether the implementation allocates from input size (make([]byte/T, n) or
//     append where n derives from parsed data) — AST heuristic, not full taint
//   - bwgen family match (A/B/U) for existing-target cross-reference
//   - risk score (0–100) with stated reasons; ranking combines:
//       1. Keyorix-caller tier (passed via -callers flag, comma-separated names)
//       2. CBC/crypto/decrypt path heuristic (function name pattern)
//       3. Verify/signature-check path heuristic
//       4. Untrusted-bytes parameter presence
//       5. Output type complexity (returns a parsed object)
//       6. Branch-count proxy for cyclomatic complexity (from AST)
//
// Portability: pass -srcdir to the package's own source directory to avoid
// workspace-contamination errors. If omitted, the current directory is used.
// The module path (-pkg) is used for JSON labelling only; actual loading uses
// whatever package resides in -srcdir.
//
// Output: JSON on stdout (or -out file) + a compact text report on stderr.
//
// Usage:
//
//	go run scripts/fuzzing/apigen/main.go \
//	  -pkg github.com/digitorus/pkcs7 \
//	  -srcdir /path/to/pkcs7@v... \
//	  -version v0.0.0-20261104125046-a476de3098e4 \
//	  -callers Parse,VerifyWithOpts \
//	  -covered FuzzDigitorusPKCS7BoundedWork:Parse \
//	  -out docs/fuzz/library-surface/api-inventory.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Symbol is one exported function or method with all analysis attributes.
type Symbol struct {
	Package     string `json:"package"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`    // "func" or "method"
	Receiver    string `json:"receiver"` // "" for package-level funcs
	Signature   string `json:"signature"`
	Parameters  []Param `json:"parameters"`
	Returns     []Return `json:"returns"`

	BwgenFamily string `json:"bwgen_family"` // "A","B","U","m","" — bwgen classification
	CanPanic    bool   `json:"can_panic"`
	PanicReason string `json:"panic_reason,omitempty"`

	AllocatesFromInput     bool   `json:"allocates_from_input"`
	AllocDetail            string `json:"alloc_detail,omitempty"`
	AllocInCallee          bool   `json:"alloc_in_callee"`  // known allocation in private helper (manual annotation)

	ReachableFromParser bool     `json:"reachable_from_parser"`
	CallerTier          int      `json:"caller_tier"` // 1=direct Keyorix caller, 2=adjacent, 3=rest
	Coverage            []string `json:"coverage"`    // fuzz target names, nil if uncovered

	BranchCount int `json:"branch_count"` // AST proxy for cyclomatic complexity

	RiskScore   int      `json:"risk_score"`
	RiskReasons []string `json:"risk_reasons"`
}

// Param is one parameter of a function/method.
type Param struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"` // untrusted-bytes / structured / handle / config
}

// Return is one return value.
type Return struct {
	Type string `json:"type"`
}

// Inventory is the top-level JSON output.
type Inventory struct {
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Date      string   `json:"date"`
	SrcDir    string   `json:"src_dir"`
	Symbols   []Symbol `json:"symbols"`
}

func main() {
	pkg     := flag.String("pkg", "", "import path to label in output (e.g. github.com/digitorus/pkcs7)")
	srcdir  := flag.String("srcdir", "", "source directory for packages.Load (defaults to current dir)")
	version := flag.String("version", "", "module version to record in output")
	date    := flag.String("date", "2026-11-20", "generation date for output")
	outFile := flag.String("out", "", "write JSON to this file instead of stdout")
	callers := flag.String("callers", "", "comma-separated symbol names directly called by the host project with untrusted input (tier 1)")
	covered := flag.String("covered", "", "comma-separated target:symbol pairs (e.g. FuzzFoo:Parse,FuzzBar:Verify)")
	flag.Parse()

	if *pkg == "" {
		fmt.Fprintln(os.Stderr, "apigen: -pkg is required")
		os.Exit(1)
	}

	dir := "."
	if *srcdir != "" {
		dir = *srcdir
	}

	// Parse callers and coverage maps.
	tier1 := map[string]bool{}
	for _, c := range splitCSV(*callers) {
		tier1[c] = true
	}
	coverageMap := map[string][]string{} // symbol → fuzz target names
	for _, pair := range splitCSV(*covered) {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			sym, tgt := parts[1], parts[0]
			coverageMap[sym] = append(coverageMap[sym], tgt)
		}
	}

	// Load the package.
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedSyntax | packages.NeedFiles | packages.NeedImports |
			packages.NeedDeps,
		Dir:  dir,
		Fset: token.NewFileSet(),
	}
	pkgs, err := packages.Load(cfg, *pkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apigen: packages.Load: %v\n", err)
		os.Exit(1)
	}

	var symbols []Symbol
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			fmt.Fprintf(os.Stderr, "apigen: load errors for %s:\n", p.PkgPath)
			for _, e := range p.Errors {
				fmt.Fprintf(os.Stderr, "  %v\n", e)
			}
		}
		if p.Types == nil {
			continue
		}

		// Build an AST index: funcDecl → branch count + doc comment.
		astIndex := buildASTIndex(p)

		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() {
				continue
			}

			switch o := obj.(type) {
			case *types.Func:
				sig := o.Type().(*types.Signature)
				if sig.Recv() != nil {
					continue // methods handled via TypeName below
				}
				s := buildSymbol(p, o, "", sig, astIndex, tier1, coverageMap)
				symbols = append(symbols, s)

			case *types.TypeName:
				named, ok := o.Type().(*types.Named)
				if !ok {
					continue
				}
				for i := range named.NumMethods() {
					m := named.Method(i)
					if !m.Exported() {
						continue
					}
					sig := m.Type().(*types.Signature)
					recv := o.Name()
					// Use pointer receiver name: "PKCS7" → "*PKCS7"
					if ptr, ok := sig.Recv().Type().(*types.Pointer); ok {
						_ = ptr
						recv = "*" + recv
					}
					s := buildSymbol(p, m, recv, sig, astIndex, tier1, coverageMap)
					symbols = append(symbols, s)
				}
			}
		}
	}

	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].Receiver != symbols[j].Receiver {
			return symbols[i].Receiver < symbols[j].Receiver
		}
		return symbols[i].Name < symbols[j].Name
	})

	// Apply risk scores after full sort.
	for i := range symbols {
		symbols[i].RiskScore, symbols[i].RiskReasons = scoreSymbol(symbols[i])
	}

	// Sort by risk descending for the report.
	byRisk := make([]Symbol, len(symbols))
	copy(byRisk, symbols)
	sort.Slice(byRisk, func(i, j int) bool {
		if byRisk[i].RiskScore != byRisk[j].RiskScore {
			return byRisk[i].RiskScore > byRisk[j].RiskScore
		}
		if byRisk[i].Receiver != byRisk[j].Receiver {
			return byRisk[i].Receiver < byRisk[j].Receiver
		}
		return byRisk[i].Name < byRisk[j].Name
	})

	inv := Inventory{
		Package: *pkg,
		Version: *version,
		Date:    *date,
		SrcDir:  dir,
		Symbols: symbols, // alphabetical
	}

	out, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "apigen: marshal: %v\n", err)
		os.Exit(1)
	}

	if *outFile != "" {
		if err := os.MkdirAll(filepath.Dir(*outFile), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "apigen: mkdir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outFile, out, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "apigen: write: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(string(out))
	}

	// Text report to stderr.
	printReport(byRisk, *pkg, *version)
}

// astEntry holds per-function AST analysis results.
type astEntry struct {
	branches       int
	docComment     string
	hasMake        bool // make([]T, n) where n could be from input
	makeDetail     string
	hasExplicitPanic bool
}

// buildASTIndex walks the syntax of a package and returns analysis per function name.
// For methods, the key is "RecvType.MethodName"; for funcs, just "FuncName".
func buildASTIndex(p *packages.Package) map[string]*astEntry {
	index := map[string]*astEntry{}
	for _, f := range p.Syntax {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			key := funcKey(fd)
			e := &astEntry{}
			if fd.Doc != nil {
				e.docComment = fd.Doc.Text()
			}
			if fd.Body != nil {
				e.branches = countBranches(fd.Body)
				e.hasMake, e.makeDetail = detectAllocFromInput(fd.Body)
				e.hasExplicitPanic = detectExplicitPanic(fd.Body)
			}
			index[key] = e
		}
	}
	return index
}

func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		recv := recvTypeName(fd.Recv.List[0].Type)
		return recv + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// countBranches counts if/for/switch/select/case statements as a branch-count proxy.
func countBranches(body *ast.BlockStmt) int {
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt,
			*ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt,
			*ast.CaseClause, *ast.CommClause:
			count++
		}
		return true
	})
	return count
}

// detectExplicitPanic reports whether a function body contains a panic() call.
// This catches cases like panic("unexpected state") that are design-level panics,
// separate from Must*-prefix contract panics.
func detectExplicitPanic(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == "panic" {
			found = true
			return false
		}
		return true
	})
	return found
}

// detectAllocFromInput looks for make([]T, expr) or make([]byte, expr) calls
// where the size argument is not a simple constant. This is a heuristic: it
// flags make() calls with non-constant size arguments as potential
// input-driven allocations.
func detectAllocFromInput(body *ast.BlockStmt) (bool, string) {
	found := false
	detail := ""
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name != "make" && ident.Name != "append" {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		// Check if any size argument is non-trivially constant.
		for _, arg := range call.Args[1:] {
			if _, isLit := arg.(*ast.BasicLit); !isLit {
				found = true
				detail = fmt.Sprintf("%s() with non-constant size arg", ident.Name)
				return false
			}
		}
		return true
	})
	return found, detail
}

// buildSymbol constructs a Symbol from a types.Func.
func buildSymbol(p *packages.Package, fn *types.Func, recv string, sig *types.Signature,
	astIndex map[string]*astEntry, tier1 map[string]bool, coverageMap map[string][]string) Symbol {

	name := fn.Name()
	kind := "func"
	if recv != "" {
		kind = "method"
	}

	// Build parameter list.
	var params []Param
	for i := range sig.Params().Len() {
		v := sig.Params().At(i)
		params = append(params, Param{
			Name:  v.Name(),
			Type:  types.TypeString(v.Type(), nil),
			Class: classifyParam(v.Type()),
		})
	}

	// Build return list.
	var returns []Return
	for i := range sig.Results().Len() {
		v := sig.Results().At(i)
		returns = append(returns, Return{Type: types.TypeString(v.Type(), nil)})
	}

	// Look up AST entry.
	astKey := name
	if recv != "" {
		recvBase := strings.TrimPrefix(recv, "*")
		astKey = recvBase + "." + name
	}
	ae := astIndex[astKey]

	canPanic := false
	panicReason := ""
	hasMake := false
	makeDetail := ""
	branches := 0
	docComment := ""

	if ae != nil {
		hasMake = ae.hasMake
		makeDetail = ae.makeDetail
		branches = ae.branches
		docComment = ae.docComment
	}

	// Panic-by-contract: Must* prefix, doc comment mentioning "panics", or explicit panic() call.
	if strings.HasPrefix(name, "Must") {
		canPanic = true
		panicReason = "Must* prefix — panics by contract"
	} else if ae != nil && ae.hasExplicitPanic {
		canPanic = true
		panicReason = "explicit panic() call in function body"
	} else if ae != nil && (strings.Contains(strings.ToLower(docComment), "panics") ||
		strings.Contains(strings.ToLower(docComment), "panic")) {
		canPanic = true
		panicReason = "doc comment mentions panic"
	}

	// Determine bwgen family.
	bwgenFamily := bwgenFamilyOf(sig, name, recv)

	// Coverage lookup: check by name, and also "ReceiverType.MethodName".
	cov := coverageMap[name]
	if len(cov) == 0 && recv != "" {
		cov = coverageMap[strings.TrimPrefix(recv, "*")+"."+name]
	}
	// Ensure nil for uncovered (not empty slice).
	if len(cov) == 0 {
		cov = nil
	}

	// Caller tier.
	callerTier := 3
	if tier1[name] {
		callerTier = 1
	} else if isAdjacentToParser(name, recv, params) {
		callerTier = 2
	}

	// Reachable from parser: returns a parsed type or takes a parsed type.
	reachable := isReachableFromParser(name, recv, sig)

	s := Symbol{
		Package:             p.PkgPath,
		Name:                name,
		Kind:                kind,
		Receiver:            recv,
		Signature:           types.ObjectString(fn, nil),
		Parameters:          params,
		Returns:             returns,
		BwgenFamily:         bwgenFamily,
		CanPanic:            canPanic,
		PanicReason:         panicReason,
		AllocatesFromInput:  hasMake,
		AllocDetail:         makeDetail,
		ReachableFromParser: reachable,
		CallerTier:          callerTier,
		Coverage:            cov,
		BranchCount:         branches,
	}
	return s
}

// classifyParam classifies a parameter type into the four input categories.
func classifyParam(t types.Type) string {
	switch t.String() {
	case "[]byte", "string", "io.Reader":
		return "untrusted-bytes"
	}
	// Pointer to known key/signer types → handle.
	switch t.String() {
	case "crypto.PrivateKey", "crypto.Signer", "interface{}",
		"any":
		return "handle"
	}
	// time.Time → config (not untrusted input).
	if t.String() == "time.Time" {
		return "config"
	}
	// crypto/x509 types: certificate pools, verify options → structured.
	ts := t.String()
	if strings.Contains(ts, "x509.") ||
		strings.Contains(ts, "asn1.") ||
		strings.Contains(ts, "pkix.") ||
		strings.Contains(ts, "pkcs7.") {
		return "structured"
	}
	// Slice of a structured type → structured.
	if strings.HasPrefix(ts, "[]*") || strings.HasPrefix(ts, "[]") {
		return "structured"
	}
	// Config-shaped types (SignerInfoConfig, VerifyOptions).
	if strings.Contains(ts, "Config") || strings.Contains(ts, "Options") ||
		strings.Contains(ts, "Opts") {
		return "config"
	}
	// Default: structured.
	return "structured"
}

// bwgenFamilyOf computes what bwgen family this symbol matches, if any.
func bwgenFamilyOf(sig *types.Signature, name, recv string) string {
	params := sig.Params()
	results := sig.Results()
	lastErr := results.Len() >= 1 && results.At(results.Len()-1).Type().String() == "error"

	isInType := func(t types.Type) bool {
		switch t.String() {
		case "[]byte", "string", "io.Reader":
			return true
		}
		return false
	}

	if recv != "" {
		// Method: check if first param is IN type (family A/B for methods).
		if params.Len() == 1 && isInType(params.At(0).Type()) {
			if results.Len() >= 1 {
				return "m" // reported-only method shape
			}
		}
		return ""
	}

	// Package-level func.
	// Family U: func(IN, any|*T) error
	if params.Len() == 2 && results.Len() == 1 && lastErr {
		if isInType(params.At(0).Type()) {
			p1 := params.At(1).Type()
			_, isIface := p1.Underlying().(*types.Interface)
			_, isPtr := p1.Underlying().(*types.Pointer)
			if isIface || isPtr {
				return "U"
			}
		}
	}
	// Family A/B: single IN param.
	if params.Len() == 1 && isInType(params.At(0).Type()) {
		if results.Len() == 2 && lastErr {
			return "A"
		}
		if results.Len() == 1 && !lastErr {
			return "B"
		}
		if results.Len() == 1 && lastErr {
			return "A"
		}
	}
	return ""
}

// isAdjacentToParser returns true for Verify*/Decrypt* methods on *PKCS7 —
// they take parsed objects produced by Parse, so they're reachable from the
// parser path.
func isAdjacentToParser(name, recv string, params []Param) bool {
	if recv == "*PKCS7" || recv == "PKCS7" {
		return true
	}
	// Functions that take *x509.Certificate or *PKCS7 as input.
	for _, p := range params {
		if strings.Contains(p.Type, "PKCS7") {
			return true
		}
	}
	return false
}

// isReachableFromParser is true for symbols that either:
// - take a *PKCS7 (the parsed output) as receiver/param, or
// - return a *PKCS7 (are the parser itself).
func isReachableFromParser(name, recv string, sig *types.Signature) bool {
	if recv == "*PKCS7" || recv == "PKCS7" {
		return true
	}
	// Returns *PKCS7 — is the parser.
	for i := range sig.Results().Len() {
		r := sig.Results().At(i).Type().String()
		if strings.Contains(r, "PKCS7") {
			return true
		}
	}
	return false
}

// scoreSymbol computes a 0-100 risk score with explicit reasons.
func scoreSymbol(s Symbol) (int, []string) {
	score := 0
	var reasons []string

	// Covered symbols get a base score only (they're handled, but not zero-risk).
	if len(s.Coverage) > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("covered-by:%s(+10)", strings.Join(s.Coverage, "+")))
	}

	// Caller tier.
	switch s.CallerTier {
	case 1:
		score += 35
		reasons = append(reasons, "keyorix-tier-1-caller(+35)")
	case 2:
		score += 25
		reasons = append(reasons, "keyorix-tier-2-adjacent(+25)")
	default:
		score += 10
		reasons = append(reasons, "not-directly-called(+10)")
	}

	// Untrusted-bytes parameter.
	for _, p := range s.Parameters {
		if p.Class == "untrusted-bytes" {
			score += 20
			reasons = append(reasons, fmt.Sprintf("untrusted-bytes-param:%s(+20)", p.Name))
			break
		}
	}

	// Decrypt/CBC/crypto path (highest risk for padding oracle, side-channel).
	nameLow := strings.ToLower(s.Name)
	if strings.Contains(nameLow, "decrypt") {
		score += 20
		reasons = append(reasons, "decrypt-path(+20)")
	} else if strings.Contains(nameLow, "verify") {
		score += 15
		reasons = append(reasons, "verify-path(+15)")
	} else if strings.Contains(nameLow, "sign") || strings.Contains(nameLow, "encrypt") {
		score += 8
		reasons = append(reasons, "sign/encrypt-path(+8)")
	}

	// Parser itself.
	if s.Name == "Parse" || strings.Contains(nameLow, "parse") {
		score += 15
		reasons = append(reasons, "is-parser(+15)")
	}

	// Allocates from input size.
	if s.AllocatesFromInput {
		score += 10
		reasons = append(reasons, "allocates-from-input(+10)")
	}

	// Can panic but NOT by contract (unexpected panic = crash finding).
	if s.CanPanic && !strings.HasPrefix(s.Name, "Must") {
		score += 8
		reasons = append(reasons, "unexpected-panic-risk(+8)")
	}

	// High branch complexity.
	if s.BranchCount >= 20 {
		score += 8
		reasons = append(reasons, fmt.Sprintf("high-complexity:branches=%d(+8)", s.BranchCount))
	} else if s.BranchCount >= 10 {
		score += 4
		reasons = append(reasons, fmt.Sprintf("moderate-complexity:branches=%d(+4)", s.BranchCount))
	}

	// Error-only return (pure validator, clean signal for fuzzing).
	if len(s.Returns) == 1 && s.Returns[0].Type == "error" {
		score += 2
		reasons = append(reasons, "pure-validator(+2)")
	}

	// Cap at 100.
	if score > 100 {
		score = 100
	}
	return score, reasons
}

// printReport writes a human-readable summary to stderr.
func printReport(byRisk []Symbol, pkg, version string) {
	total := len(byRisk)
	covered := 0
	uncovered := 0
	for _, s := range byRisk {
		if len(s.Coverage) > 0 {
			covered++
		} else {
			uncovered++
		}
	}

	fmt.Fprintf(os.Stderr, "\n== apigen: %s %s ==\n", pkg, version)
	fmt.Fprintf(os.Stderr, "Total exported symbols: %d\n", total)
	fmt.Fprintf(os.Stderr, "  Covered:   %d\n", covered)
	fmt.Fprintf(os.Stderr, "  Uncovered: %d\n\n", uncovered)

	// Parameter class counts.
	classCounts := map[string]int{}
	for _, s := range byRisk {
		for _, p := range s.Parameters {
			classCounts[p.Class]++
		}
	}
	fmt.Fprintln(os.Stderr, "Parameter classes:")
	for _, c := range []string{"untrusted-bytes", "structured", "handle", "config"} {
		fmt.Fprintf(os.Stderr, "  %-20s %d\n", c, classCounts[c])
	}
	fmt.Fprintln(os.Stderr)

	// Top 20 by risk.
	top := byRisk
	if len(top) > 20 {
		top = top[:20]
	}
	fmt.Fprintln(os.Stderr, "Top symbols by risk score:")
	fmt.Fprintf(os.Stderr, "  %-6s %-6s %-40s %s\n", "SCORE", "COV?", "SYMBOL", "TOP REASON")
	for _, s := range top {
		cov := " "
		if len(s.Coverage) > 0 {
			cov = "Y"
		}
		sym := s.Name
		if s.Receiver != "" {
			sym = "(" + s.Receiver + ")." + s.Name
		}
		topReason := ""
		if len(s.RiskReasons) > 0 {
			topReason = s.RiskReasons[0]
		}
		fmt.Fprintf(os.Stderr, "  %-6d %-6s %-40s %s\n", s.RiskScore, cov, sym, topReason)
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
