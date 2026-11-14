// Command sinkmap lists dangerous SINK call sites in the root module, by
// kind, and for each one reports its enclosing function, whether that
// function is reachable from an API / parser entry point, and whether it is
// already within two call hops of a Fuzz target. It emits a ranked,
// machine-readable table (TSV) plus a Markdown summary.
//
// It is a TARGETING tool for choosing where to point a fuzz harness next —
// NOT a vulnerability scanner and NOT a verdict. A row never asserts a bug.
//
// Design (deliberately offline and deterministic — no network, no external
// SAST service, no timestamps, no models):
//
//   - Parsing is go/parser + go/ast only. golang.org/x/tools/go/packages
//     (with go/types) is present in the module cache and would improve
//     precision for the type-dependent sinks (http.Client.Do receiver,
//     json/yaml/xml Unmarshal target type, []byte-vs-string compare), but
//     full-module type checking is costly on a constrained host and every
//     existing in-repo analysis tool (scripts/fuzzing/invariant-map,
//     autofuzzgen) is AST-only for the same reason. Where a classification
//     would need types, the matcher says so in its Detail text instead of
//     guessing.
//
//   - The static call graph is NAME-BASED: a call `x.Foo(...)` resolves to
//     every declaration named Foo in the module. This over-approximates
//     reachability, which is the safe direction for a targeting tool.
//
// What this tool does NOT verify (see the matchers in sinks.go and the
// generated report's "oracle limitations" section):
//
//   - It does not prove any sink is actually attacker-reachable with
//     attacker-controlled data — only that a syntactic call graph connects
//     an entry package to it.
//   - "fuzz_covered=yes" can be over-claimed through same-name edges, so the
//     real uncovered set is a SUPERSET of what is flagged uncovered.
//   - Sinks in package-level var initialisers (outside any FuncDecl) are not
//     listed; only sinks inside function bodies are.
//
// Usage (from the repository root):
//
//	go run ./scripts/fuzzing/sinkmap -tsv out.tsv -md out.md
//	go run ./scripts/fuzzing/sinkmap -check          # fail if the committed table is stale
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("sinkmap", flag.ContinueOnError)
	fs.SetOutput(errw)
	root := fs.String("root", ".", "root module directory")
	tsvOut := fs.String("tsv", "", "write the full TSV table to this file")
	mdOut := fs.String("md", "", "write the Markdown report to this file")
	topN := fs.Int("top", 15, "how many top uncovered API-reachable sinks to list in Markdown")
	check := fs.Bool("check", false, "verify the committed TSV matches a fresh scan; nonzero exit on drift")
	stdoutMD := fs.Bool("stdout", false, "print the Markdown report to stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	res, err := scanModule(*root, false)
	if err != nil {
		fmt.Fprintln(errw, "sinkmap:", err)
		return 1
	}
	classify(res)

	var tsv strings.Builder
	writeTSV(res, &tsv)

	if *check {
		committed := filepath.Join(*root, committedTSV)
		data, err := os.ReadFile(committed)
		if err != nil {
			fmt.Fprintf(errw, "sinkmap -check: cannot read %s: %v\n", committedTSV, err)
			return 1
		}
		if string(data) != tsv.String() {
			fmt.Fprintf(errw, "sinkmap -check: %s is stale; regenerate with:\n  go run ./scripts/fuzzing/sinkmap -tsv %s\n", committedTSV, committedTSV)
			return 1
		}
		fmt.Fprintln(out, "sinkmap -check: committed table is up to date")
		return 0
	}

	if *tsvOut != "" {
		if err := os.WriteFile(*tsvOut, []byte(tsv.String()), 0o644); err != nil {
			fmt.Fprintln(errw, "sinkmap:", err)
			return 1
		}
	}
	var md strings.Builder
	writeMarkdown(res, *topN, &md)
	if *mdOut != "" {
		if err := os.WriteFile(*mdOut, []byte(md.String()), 0o644); err != nil {
			fmt.Fprintln(errw, "sinkmap:", err)
			return 1
		}
	}
	if *stdoutMD || (*tsvOut == "" && *mdOut == "") {
		fmt.Fprint(out, md.String())
	}
	return 0
}

// committedTSV is the module-relative path of the checked-in table that
// `-check` validates against.
const committedTSV = "scripts/fuzzing/sinkmap/SINKS.tsv"
