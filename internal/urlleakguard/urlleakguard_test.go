package urlleakguard

// urlleakguard_test.go — the CLASS guard for REDACT-URLS-1: a configured
// endpoint, URL or DSN is formatted verbatim into a log line or an error.
// These values can carry a token (userinfo, a path token as in Slack-style
// webhooks, a ?key= query, a DSN password), so naming the destination in
// diagnostics is only safe through netutil.RedactURLHost / RedactErrorURLs.
//
// # What the guard recognises
//
//   - CALLS: the package-qualified forms log.Print*/Fatal*/Panic*, fmt.Errorf,
//     errors.New and slog.Debug/Info/Warn/Error/Log (and their Context forms).
//   - ARGUMENTS: a bare identifier or selector whose final name is one of
//     Endpoint, URL, Url, DSN, WebhookURL (matched case-insensitively as a
//     whole name or as a suffix of a camel-case name: cfg.Endpoint,
//     c.WebhookURL, req.URL, dsn, rawURL, endpointURL), including as an operand
//     of a string concatenation.
//   - VERBS: for a Printf-style call with a literal format string, only an
//     argument that lands on %v, %+v, %#v, %s or %q is a hit (%w, %d, %t, %p
//     are not). slog and Print/Println take values with no verb, and a non-
//     literal format string is checked conservatively, so every such argument
//     is a hit.
//   - SANCTIONED: the argument is any call expression, e.g.
//     netutil.RedactURLHost(cfg.Endpoint), u.Hostname() or u.Redacted(): the
//     guard never looks inside a call, so wrapping is the way to satisfy it.
//
// # What it does not recognise
//
//   - Methods on a logger value (l.Printf, s.logger.Info, t.Logf) and any
//     wrapper function around log: only the package-qualified calls above. A
//     third-party logger or a project helper that logs is invisible to it.
//   - A value that does not carry such a name (err, a *url.Error wrapped with
//     %w, a struct printed with %+v that contains a URL field, a variable
//     named target or addr that holds a URL). Renaming defeats it.
//   - Reflection, and tests (_test.go files are skipped).
//   - Separate Go modules inside the tree (cli/, operator/, migrate/,
//     devtools/): the walk stops at any directory with its own go.mod.
//
// The guard is shape-based like internal/dynamic's log_redaction_guard_test.go,
// not type-aware: pulling go/packages in would type-check the whole module for
// a name heuristic that does not need types. TestURLLeakScannerDetectsShapes
// is its red proof and keeps the scanner honest in both directions.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// leakExemptions are repo-relative files the guard deliberately skips, each
// with the reason and the work that removes the exemption.
var leakExemptions = map[string]string{
	// Audit-adjacent and owned by OPT-AUDIT-RT-1; recorded as a LEFTOVER of
	// REDACT-URLS-1 with the exact lines. Remove when that session lands.
	"internal/audit/siem/forwarder.go": "OPT-AUDIT-RT-1 owns it",
	// A developer measurement tool, not product code: requireLoopbackURL
	// (same file) refuses any non-loopback p.URL before it is ever formatted.
	"scripts/metrics/surfacewalk/startup.go": "loopback-only dev tool",
}

// skippedDirs are never walked.
var skippedDirs = map[string]bool{
	".git": true, ".scratch": true, ".claude": true, "node_modules": true,
	"vendor": true, "testdata": true, "tmp": true,
}

// sensitiveName reports whether an identifier names an endpoint/URL/DSN value.
func sensitiveName(name string) bool {
	l := strings.ToLower(name)
	for _, suffix := range []string{"endpoint", "url", "dsn"} {
		if !strings.HasSuffix(l, suffix) {
			continue
		}
		// A bare name (endpoint, URL, dsn), or a camel-case/underscore suffix
		// (WebhookURL, rawURL, endpoint_url). A name like "curl" or "hurl"
		// that merely ends in the letters is not one.
		if len(name) == len(suffix) {
			return true
		}
		cut := name[len(name)-len(suffix):]
		prev := name[len(name)-len(suffix)-1]
		if prev == '_' || (cut[0] >= 'A' && cut[0] <= 'Z') || (name == strings.ToUpper(name)) {
			return true
		}
	}
	return false
}

// sensitiveExpr returns the offending name when e is an identifier or
// selector with a sensitive name, or a concatenation containing one. Calls are
// never inspected: wrapping in a call is the sanctioned shape.
func sensitiveExpr(e ast.Expr) (string, bool) {
	switch v := ast.Unparen(e).(type) {
	case *ast.Ident:
		if sensitiveName(v.Name) {
			return v.Name, true
		}
	case *ast.SelectorExpr:
		if sensitiveName(v.Sel.Name) {
			return exprString(v), true
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			if n, ok := sensitiveExpr(v.X); ok {
				return n, true
			}
			return sensitiveExpr(v.Y)
		}
	}
	return "", false
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	}
	return "?"
}

// leakyVerb reports whether a printf verb prints its operand's text.
func leakyVerb(v string) bool {
	switch v {
	case "v", "+v", "#v", "s", "q", "+s", "+q":
		return true
	}
	return false
}

// verbsOf returns the verb of each operand-consuming directive in format, in
// order ("%%" consumes nothing; "%*d" consumes an extra operand for the star).
func verbsOf(format string) []string {
	var verbs []string
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		start := i
		for i < len(format) && strings.IndexByte("+-# 0123456789.*[]", format[i]) >= 0 {
			if format[i] == '*' {
				verbs = append(verbs, "*")
			}
			i++
		}
		if i >= len(format) {
			break
		}
		if format[i] == '%' {
			continue
		}
		flags := format[start:i]
		verb := string(format[i])
		if strings.ContainsAny(flags, "+#") {
			verb = strings.Trim(flags, "-0123456789.*[] ") + verb
		}
		verbs = append(verbs, verb)
	}
	return verbs
}

// leakHit is one flagged call argument.
type leakHit struct {
	file string
	line int
	call string
	name string
}

func (h leakHit) String() string {
	return fmt.Sprintf("%s:%d: %s formats %s verbatim", h.file, h.line, h.call, h.name)
}

// printfStyle lists the package-qualified calls whose first argument is a format.
var printfStyle = map[string]map[string]bool{
	"log": {"Printf": true, "Fatalf": true, "Panicf": true},
	"fmt": {"Errorf": true},
}

// plainStyle lists the package-qualified calls with no format string. For slog
// every key/value argument is a value position as far as this guard cares.
var plainStyle = map[string]map[string]bool{
	"log":    {"Print": true, "Println": true, "Fatal": true, "Fatalln": true, "Panic": true, "Panicln": true},
	"errors": {"New": true},
	"slog": {
		"Debug": true, "Info": true, "Warn": true, "Error": true,
		"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
		"Log": true,
	},
}

// findLeaks scans one parsed file.
func findLeaks(fset *token.FileSet, file *ast.File, path string) []leakHit {
	var hits []leakHit
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		name := pkg.Name + "." + sel.Sel.Name
		add := func(arg ast.Expr, what string) {
			hits = append(hits, leakHit{path, fset.Position(arg.Pos()).Line, name, what})
		}
		switch {
		case printfStyle[pkg.Name][sel.Sel.Name]:
			if len(call.Args) == 0 {
				return true
			}
			operands := call.Args[1:]
			var verbs []string
			literal := false
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					verbs, literal = verbsOf(s), true
				}
			}
			for i, arg := range operands {
				what, bad := sensitiveExpr(arg)
				if !bad {
					continue
				}
				// Non-literal format: unknown verb, conservatively a hit.
				if !literal || (i < len(verbs) && leakyVerb(verbs[i])) {
					add(arg, what)
				}
			}
		case plainStyle[pkg.Name][sel.Sel.Name]:
			for _, arg := range call.Args {
				if what, bad := sensitiveExpr(arg); bad {
					add(arg, what)
				}
			}
		}
		return true
	})
	return hits
}

// repoRoot is the module root, two levels above this package.
func repoRoot() string { return filepath.Join("..", "..") }

func TestNoConfiguredURLFormattedIntoLogsOrErrors(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot()
	fset := token.NewFileSet()
	var hits []leakHit
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skippedDirs[d.Name()] && rel != "." {
				return filepath.SkipDir
			}
			if rel != "." {
				if _, statErr := os.Stat(filepath.Join(p, "go.mod")); statErr == nil {
					return filepath.SkipDir // a separate module (cli/, operator/, ...)
				}
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if _, skip := leakExemptions[rel]; skip {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return fmt.Errorf("parsing %s: %w", rel, perr)
		}
		scanned++
		hits = append(hits, findLeaks(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 500 {
		t.Fatalf("scanned only %d Go files; the walk root or skip list broke silently", scanned)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].file != hits[j].file {
			return hits[i].file < hits[j].file
		}
		return hits[i].line < hits[j].line
	})
	for _, h := range hits {
		g.Errorf("%s -- name the destination with netutil.RedactURLHost(...) and strip a wrapped "+
			"*url.Error with netutil.RedactErrorURLs(...); a configured URL/DSN can carry a token", h)
	}
}

// TestLeakExemptionsExist keeps the exemption list from outliving its file.
func TestLeakExemptionsExist(t *testing.T) {
	for rel := range leakExemptions {
		if _, err := os.Stat(filepath.Join(repoRoot(), filepath.FromSlash(rel))); err != nil {
			t.Errorf("exempted file %s no longer exists (%v): remove the exemption", rel, err)
		}
	}
}

// TestURLLeakScannerDetectsShapes is the red proof: it must flag every
// violating shape and must not flag the sanctioned or unrelated ones.
func TestURLLeakScannerDetectsShapes(t *testing.T) {
	const src = `package fixture

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
)

func bad(cfg Config, c Client, dsn, rawURL string, err error) {
	log.Printf("endpoint %q", cfg.Endpoint)                    // 1 %q
	log.Printf("a=%d b=%s", 1, c.WebhookURL)                   // 2 second operand, %s
	log.Println("failed:", dsn)                                // 3 Println
	_ = fmt.Errorf("bad %v: %w", rawURL, err)                  // 4 %v before %w
	_ = errors.New("bad endpoint " + cfg.Endpoint)             // 5 concatenation
	slog.Warn("x", "url", c.Url)                               // 6 slog value
	log.Printf(format, cfg.URL)                                // 7 non-literal format
	_ = fmt.Errorf("%+v", cfg.Endpoint)                        // 8 %+v
}

func good(cfg Config, c Client, dsn string, err error, curl string) {
	log.Printf("endpoint %q", netutil.RedactURLHost(cfg.Endpoint)) // wrapped in a call
	log.Printf("n=%d", cfg.URL)                                    // %d is not a text verb
	_ = fmt.Errorf("wrap: %w", cfg.Endpoint)                       // %w is the error operand
	log.Println("failed:", err)                                    // not a sensitive name
	log.Println(curl)                                              // ends in the letters but is not a URL name
	l.Printf("endpoint %q", cfg.Endpoint)                          // method on a logger value: not tracked
	fmt.Printf("endpoint %q", cfg.Endpoint)                        // stdout, not a log or an error
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	hits := findLeaks(fset, file, "fixture.go")
	got := map[int]bool{}
	for _, h := range hits {
		got[h.line] = true
	}
	for line := 11; line <= 18; line++ {
		if !got[line] {
			t.Errorf("fixture line %d (violating shape %d) was not flagged; hits: %v", line, line-10, hits)
		}
	}
	for _, h := range hits {
		if h.line > 18 {
			t.Errorf("sanctioned or unrelated shape flagged: %s", h)
		}
	}
	if len(hits) != 8 {
		t.Errorf("flagged %d, want exactly 8: %v", len(hits), hits)
	}
}

// TestSensitiveName pins the name matcher, including near-misses.
func TestSensitiveName(t *testing.T) {
	for _, n := range []string{"Endpoint", "URL", "Url", "DSN", "WebhookURL", "dsn", "rawURL", "endpoint", "url", "endpointURL", "endpoint_url", "BaseURL"} {
		if !sensitiveName(n) {
			t.Errorf("%q should be sensitive", n)
		}
	}
	for _, n := range []string{"curl", "hurl", "Burl", "err", "Path", "Host", "EndpointCount", "URLs", "pdsn"} {
		if sensitiveName(n) {
			t.Errorf("%q should not be sensitive", n)
		}
	}
}
