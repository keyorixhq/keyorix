// report.go — classify each sink (API-reachable? fuzz-covered?) over the
// name-based call graph, rank the uncovered ones, and render TSV + Markdown.
//
// Reachability is a CONSERVATIVE over-approximation: call edges resolve by
// simple name across the whole module, so a sink marked "api=yes" may be
// reachable only through a same-named-but-unrelated function. This is the
// safe direction for a *targeting* tool (it widens the candidate set rather
// than hiding a real gap) — but it means "fuzz=yes" can also be
// over-claimed, so the true uncovered set is a SUPERSET of what is listed as
// uncovered. Top candidates must be hand-verified (see REPORT).
package main

import (
	"fmt"
	"sort"
	"strings"
)

// entryPrefixes are the module-relative package dirs whose EXPORTED
// functions/methods are treated as API / parser entry roots. CLI entry
// points live in the separate `cli/` module (its own go.mod) and are out of
// the root module's scope; the archive/config parsers below stand in for the
// "archive/config parser" entry class named in the task.
var entryPrefixes = []string{
	"server/http",
	"server/grpc",
	"server/middleware",
	"internal/backupfmt", // archive parser/loader
	"internal/config",    // config parser
}

// nonProductPrefixes are root-module package dirs that hold developer/CI
// tooling rather than shipped product code. Sinks there are still listed in
// the full TSV, but excluded from the "product entry-point" top-N.
var nonProductPrefixes = []string{"scripts", "tools"}

func isProductPkg(pkg string) bool {
	for _, p := range nonProductPrefixes {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return false
		}
	}
	return true
}

func isEntryPkg(pkg string) bool {
	for _, p := range entryPrefixes {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return true
		}
	}
	return false
}

func isExported(name string) bool {
	return name != "" && name[0] >= 'A' && name[0] <= 'Z'
}

// classify fills APIReachable/APIEntry and FuzzCovered/FuzzBy on every sink.
func classify(res *scanResult) {
	// API-reachable: downstream BFS from every exported func/method in an
	// entry package. No depth cap beyond a visited set (reachable = reachable).
	apiReached := map[string]string{} // funcDisplay -> originating entry root
	var apiRoots []*fnDecl
	for _, f := range res.Funcs {
		if !f.IsTest && isEntryPkg(f.Pkg) && (isExported(f.Name) || f.Recv != "") {
			apiRoots = append(apiRoots, f)
		}
	}
	sort.Slice(apiRoots, func(i, j int) bool { return apiRoots[i].Display < apiRoots[j].Display })
	for _, root := range apiRoots {
		bfsMark(res, root, -1, root.Display, apiReached)
	}

	// Fuzz coverage: downstream BFS depth<=2 from every Fuzz target.
	fuzzReached := map[string]string{}
	var fuzzRoots []*fnDecl
	for _, f := range res.Funcs {
		if f.IsFuzz {
			fuzzRoots = append(fuzzRoots, f)
		}
	}
	sort.Slice(fuzzRoots, func(i, j int) bool { return fuzzRoots[i].Display < fuzzRoots[j].Display })
	for _, root := range fuzzRoots {
		bfsMark(res, root, 2, root.Display, fuzzReached)
	}

	for i := range res.Sinks {
		s := &res.Sinks[i]
		s.Product = isProductPkg(s.Pkg)
		// A sink's enclosing func is itself an entry root ⇒ reachable.
		if fd := res.byDisp[s.Func]; fd != nil && isEntryPkg(fd.Pkg) && (isExported(fd.Name) || fd.Recv != "") {
			s.APIReachable = true
			if s.APIEntry == "" {
				s.APIEntry = s.Func + " (is-entry)"
			}
		}
		if e, ok := apiReached[s.Func]; ok {
			s.APIReachable = true
			if s.APIEntry == "" {
				s.APIEntry = e
			}
		}
		if by, ok := fuzzReached[s.Func]; ok {
			s.FuzzCovered = true
			s.FuzzBy = by
		}
	}
}

// bfsMark marks every function reachable from root (depth<=maxDepth, or
// unbounded when maxDepth<0) with the originating root's display name.
// Edges resolve call names to every same-named declaration (over-approx).
func bfsMark(res *scanResult, root *fnDecl, maxDepth int, originLabel string, reached map[string]string) {
	type item struct {
		fn    *fnDecl
		depth int
	}
	queue := []item{{root, 0}}
	localSeen := map[string]bool{root.Display: true}
	visit := func(target *fnDecl, depth int) {
		if target == nil || target.IsTest {
			return // don't route reachability through test code
		}
		if localSeen[target.Display] {
			return
		}
		localSeen[target.Display] = true
		if _, ok := reached[target.Display]; !ok {
			reached[target.Display] = originLabel
		}
		queue = append(queue, item{target, depth})
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if maxDepth >= 0 && cur.depth >= maxDepth {
			continue
		}
		// Precise package-qualified edges.
		for _, q := range cur.fn.QCalls {
			visit(res.byPkgFunc[q], cur.depth+1)
		}
		// Over-approx method-name edges (receiver type unresolved).
		for _, callee := range cur.fn.Calls {
			for _, target := range res.byName[callee] {
				visit(target, cur.depth+1)
			}
		}
	}
}

// rankUncovered returns uncovered sinks ordered most-interesting first:
// API-reachable before not, then by kind severity, then file:line.
func rankUncovered(res *scanResult) []Sink {
	var u []Sink
	for _, s := range res.Sinks {
		if !s.FuzzCovered {
			u = append(u, s)
		}
	}
	sort.SliceStable(u, func(i, j int) bool {
		a, b := u[i], u[j]
		if a.APIReachable != b.APIReachable {
			return a.APIReachable // true first
		}
		if kindSeverity[a.Kind] != kindSeverity[b.Kind] {
			return kindSeverity[a.Kind] < kindSeverity[b.Kind]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return u
}

// counts returns per-kind totals: total, uncovered, api-reachable-uncovered.
type kindCount struct{ Total, Uncovered, APIUncovered int }

func countByKind(res *scanResult) map[SinkKind]*kindCount {
	m := map[SinkKind]*kindCount{}
	for _, s := range res.Sinks {
		c := m[s.Kind]
		if c == nil {
			c = &kindCount{}
			m[s.Kind] = c
		}
		c.Total++
		if !s.FuzzCovered {
			c.Uncovered++
			if s.APIReachable && s.Product {
				c.APIUncovered++
			}
		}
	}
	return m
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// writeTSV renders the full machine-readable table (one row per sink).
func writeTSV(res *scanResult, w *strings.Builder) {
	w.WriteString("kind\tfile\tline\tenclosing_func\tproduct\tapi_reachable\tfuzz_covered\tdetail\n")
	for _, s := range res.Sinks {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			s.Kind, s.File, s.Line, s.Func, yn(s.Product), yn(s.APIReachable), yn(s.FuzzCovered), s.Detail)
	}
}

// writeMarkdown renders the human report: counts + top-N uncovered,
// API-reachable sinks.
func writeMarkdown(res *scanResult, topN int, w *strings.Builder) {
	kinds := []SinkKind{KindExec, KindSQL, KindNetOut, KindFSPath, KindDeserialize, KindTemplate, KindCryptoCompare}
	counts := countByKind(res)
	w.WriteString("# sinkmap — sink-guided fuzz targeting (root module)\n\n")
	w.WriteString("Offline, deterministic AST analysis. This is a TARGETING table, not a vulnerability verdict.\n\n")
	w.WriteString("## Counts per sink kind\n\n")
	w.WriteString("| kind | total | uncovered | uncovered & API-reachable |\n")
	w.WriteString("|------|------:|----------:|--------------------------:|\n")
	var tT, tU, tA int
	for _, k := range kinds {
		c := counts[k]
		if c == nil {
			c = &kindCount{}
		}
		fmt.Fprintf(w, "| %s | %d | %d | %d |\n", k, c.Total, c.Uncovered, c.APIUncovered)
		tT += c.Total
		tU += c.Uncovered
		tA += c.APIUncovered
	}
	fmt.Fprintf(w, "| **total** | **%d** | **%d** | **%d** |\n\n", tT, tU, tA)

	if len(res.skipped) > 0 {
		fmt.Fprintf(w, "_Nested modules skipped (separate go.mod, out of root-module scope): %s_\n\n", strings.Join(res.skipped, ", "))
	}

	u := rankUncovered(res)
	var api []Sink
	for _, s := range u {
		if s.APIReachable && s.Product {
			api = append(api, s)
		}
	}
	fmt.Fprintf(w, "## Top %d uncovered sinks reachable from an API / parser entry point\n\n", topN)
	w.WriteString("_Product packages only (dev tooling under scripts/ and tools/ excluded)._\n\n")
	w.WriteString("| # | kind | file:line | enclosing func | detail |\n")
	w.WriteString("|--:|------|-----------|----------------|--------|\n")
	for i, s := range api {
		if i >= topN {
			break
		}
		fmt.Fprintf(w, "| %d | %s | %s:%d | `%s` | %s |\n", i+1, s.Kind, s.File, s.Line, s.Func, s.Detail)
	}
	w.WriteString("\n")
}
