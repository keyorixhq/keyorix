// egress_guard_test.go — the structural guard for the unified egress-guard
// fix (2e): no code path in the MongoDB/Redis dynamic-secret backends
// (internal/dynamic/mongodb.go, internal/dynamic/redis.go) or the SIEM/audit
// forwarder (internal/audit/siem/forwarder.go) may open a raw, unguarded
// outbound connection that bypasses the shared netutil.Dialer/netutil.Guard
// egress guard.
//
// Two independent checks, an AST walk over each scanned file (go/parser, not
// a regex/string scan — the same style as server/http's
// raw_storage_bypass_guard_test.go):
//
//   - forbiddenRawDialUses: net.Dial/net.DialTimeout/a literal net.Dialer{}
//     value, found ANYWHERE in the scanned files. There is no legitimate
//     reason for internal/dynamic or internal/audit/siem to construct one of
//     these directly — the shared guard (netutil.Dialer/netutil.Guard) is the
//     only sanctioned way to open an outbound connection from these packages;
//     netutil's own internal fallback (a plain net.Dialer{} default, used
//     only when a Dialer's own Dial field is unset) lives inside
//     internal/netutil itself, a different, unscanned package.
//   - unguardedDriverConstruction: a driver/http-client construction call
//     (mongo.Connect, redis.NewClient/NewUniversalClient/NewFailoverClient/
//     NewClusterClient, a `http.Client{}`/`&http.Client{}` composite literal)
//     found OUTSIDE the one file per backend that legitimately makes it
//     (mongodb.go/redis.go/forwarder.go), OR found INSIDE that file but in a
//     function whose body never references netutil.Dialer/netutil.Guard —
//     i.e. the construction exists, but nothing wires the guard to it. This
//     is the check that actually caught the pre-fix gap: before 2b,
//     connectMongo/connectRedis called mongo.Connect/redis.NewClient with
//     ZERO reference to netutil anywhere in the function, and the SIEM
//     forwarder built a bare &http.Transport{} with no DialContext at all —
//     confirmed RED against that code (see this file's own test,
//     TestNoUnguardedEgress, and the campaign notes on verifying red-before-
//     green). A future backend that adds a second, forgotten driver-connect
//     call site (the sibling-miss shape this campaign repeatedly finds) trips
//     this the same way.
package dynamic

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// egressGuardScanDir is one directory this guard scans, plus the single file
// within it (if any) allowed to construct a driver client / http.Client
// directly — the legitimate implementation site for that backend's guarded
// connect helper.
type egressGuardScanDir struct {
	dir         string
	allowedFile string
}

var egressGuardScanDirs = []egressGuardScanDir{
	{dir: ".", allowedFile: "mongodb.go"},                                    // MongoDB dynamic-secret backend
	{dir: ".", allowedFile: "redis.go"},                                      // Redis dynamic-secret backend
	{dir: filepath.Join("..", "audit", "siem"), allowedFile: "forwarder.go"}, // SIEM/audit forwarder
}

// knownOutOfScopeEgressFiles are files this walk finds a raw http.Client
// construction in that are DELIBERATELY not covered by this fix -- named
// explicitly so the exclusion is visible and auditable rather than a case
// this guard silently never looked at.
//
// internal/dynamic/kubernetes.go's realK8sMinter builds a raw *http.Client
// with no DialContext (found during this fix's repo-wide enumeration -- the
// same unguarded-egress shape as Mongo/Redis/SIEM before this change).
// NOT fixed here: unlike Mongo/Redis/SIEM (all external, off-box network
// targets where refusing a private/link-local resolved address is
// unconditionally the right default), a Kubernetes api_server is routinely,
// LEGITIMATELY a private RFC-1918 address (kubernetes.go's own doc comment
// example: "api_server":"https://10.0.0.1:443") -- wiring the same
// IsPrivateOrLinkLocal policy here by default would break the common,
// intended case, not just an attacker's. Closing this gap correctly needs
// its own threat-model decision (what, if anything, should be disallowed for
// an api_server target) that this change's scope (2b-2e, explicitly Mongo/
// Redis/SIEM) does not make for it. Tracked as a known, reasoned exclusion,
// not silently missed.
var knownOutOfScopeEgressFiles = map[string]map[string]bool{
	".": {"kubernetes.go": true},
}

// scanEgressGuardDir returns every non-test .go file in dir, parsed.
func scanEgressGuardDir(t *testing.T, dir string) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = f
	}
	return files
}

// identSel reports the (X, Sel) of a SelectorExpr whose X is a bare
// identifier — e.g. net.Dial → ("net", "Dial").
func egressIdentSel(e ast.Expr) (pkg, sel string, ok bool) {
	se, isSel := e.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	id, isIdent := se.X.(*ast.Ident)
	if !isIdent {
		return "", "", false
	}
	return id.Name, se.Sel.Name, true
}

var forbiddenRawDialSelectors = map[string]bool{
	"Dial":        true, // net.Dial
	"DialTimeout": true, // net.DialTimeout
}

var driverConstructionSelectors = map[string]bool{
	"Connect":            true, // mongo.Connect
	"NewClient":          true, // redis.NewClient
	"NewUniversalClient": true, // redis.NewUniversalClient
	"NewFailoverClient":  true, // redis.NewFailoverClient
	"NewClusterClient":   true, // redis.NewClusterClient
}

// findForbiddenRawDial returns a description of every net.Dial/net.DialTimeout
// call, and every literal net.Dialer{} composite literal, in file.
func findForbiddenRawDial(file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			if pkg, sel, ok := egressIdentSel(e.Fun); ok && pkg == "net" && forbiddenRawDialSelectors[sel] {
				found = append(found, "net."+sel+"(...) called directly")
			}
		case *ast.CompositeLit:
			if sel, ok := e.Type.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "net" && sel.Sel.Name == "Dialer" {
					found = append(found, "net.Dialer{...} constructed directly")
				}
			}
		}
		return true
	})
	return found
}

// funcBodyReferencesNetutilGuard reports whether fd's body references
// netutil.Dialer or netutil.Guard anywhere — the structural signal that SOME
// guard wiring happens in the same function that opens the connection.
func funcBodyReferencesNetutilGuard(fd *ast.FuncDecl) bool {
	if fd.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "netutil" && (sel.Sel.Name == "Dialer" || sel.Sel.Name == "Guard") {
			found = true
		}
		return true
	})
	return found
}

// driverConstructionIssue describes one flagged driver/http-client
// construction call site.
type driverConstructionIssue struct {
	call   string
	reason string
}

// findUnguardedDriverConstruction walks every top-level function in file and
// returns an issue for each mongo.Connect / redis.New*Client /
// http.Client{}/&http.Client{} construction whose enclosing function body
// does not also reference netutil.Dialer/netutil.Guard.
func findUnguardedDriverConstruction(file *ast.File) []driverConstructionIssue {
	var issues []driverConstructionIssue
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		guarded := funcBodyReferencesNetutilGuard(fd)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			var call string
			switch e := n.(type) {
			case *ast.CallExpr:
				if pkg, sel, ok := egressIdentSel(e.Fun); ok && driverConstructionSelectors[sel] &&
					(pkg == "mongo" || pkg == "redis") {
					call = pkg + "." + sel + "(...)"
				}
			case *ast.CompositeLit:
				if sel, ok := e.Type.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" && sel.Sel.Name == "Client" {
						call = "http.Client{...}"
					}
				}
			}
			if call == "" {
				return true
			}
			if !guarded {
				issues = append(issues, driverConstructionIssue{
					call:   call,
					reason: "in function " + fd.Name.Name + "() with no netutil.Dialer/netutil.Guard reference anywhere in its body",
				})
			}
			return true
		})
	}
	return issues
}

// TestNoUnguardedEgress is the guard: every driver/http-client construction
// in the scanned backends must be wired through the shared egress guard.
// Verified RED against the pre-2b code (mongodb.go/redis.go had zero
// netutil reference in connectMongo/connectRedis; forwarder.go built a bare
// &http.Transport{} with no DialContext) and GREEN after.
func TestNoUnguardedEgress(t *testing.T) {
	seenDirs := map[string]map[string]*ast.File{}
	allowedFiles := map[string]map[string]bool{}
	for _, sd := range egressGuardScanDirs {
		if _, ok := seenDirs[sd.dir]; !ok {
			seenDirs[sd.dir] = scanEgressGuardDir(t, sd.dir)
			allowedFiles[sd.dir] = map[string]bool{}
		}
		allowedFiles[sd.dir][sd.allowedFile] = true
	}

	for dir, files := range seenDirs {
		if len(files) == 0 {
			t.Fatalf("scanned directory %q yielded zero .go files -- the walk likely broke silently", dir)
		}
		for name, file := range files {
			for _, msg := range findForbiddenRawDial(file) {
				t.Errorf("%s/%s: forbidden raw dial: %s -- outbound connections from this package must go "+
					"through netutil.Dialer/netutil.Guard, never construct a raw net.Dial/net.Dialer{} directly",
					dir, name, msg)
			}
			if !allowedFiles[dir][name] {
				issues := findUnguardedDriverConstructionAnyFunc(file)
				if knownOutOfScopeEgressFiles[dir][name] {
					if len(issues) == 0 {
						t.Errorf("%s/%s is listed in knownOutOfScopeEgressFiles but no longer constructs a "+
							"raw driver/http.Client at all -- remove it from the exclusion list (fixed and forgotten)",
							dir, name)
					}
					continue
				}
				// Not the designated implementation file for any backend --
				// it must not construct a driver client / http.Client at all.
				for _, issue := range issues {
					t.Errorf("%s/%s: %s found outside its backend's designated guarded-connect file -- "+
						"every driver/http-client construction site must live in the one file that wires "+
						"the shared egress guard, not be duplicated elsewhere", dir, name, issue)
				}
				continue
			}
			for _, issue := range findUnguardedDriverConstruction(file) {
				t.Errorf("%s/%s: %s %s -- every driver/http-client construction site in this file must be "+
					"wired through netutil.Dialer/netutil.Guard in the SAME function, or a future call site "+
					"can silently reintroduce the unguarded-egress gap this test exists to catch",
					dir, name, issue.call, issue.reason)
			}
		}
	}
}

// findUnguardedDriverConstructionAnyFunc is findUnguardedDriverConstruction's
// sibling for a file that isn't any backend's designated implementation file
// at all: ANY driver/http.Client construction there is itself the problem,
// regardless of whether netutil is referenced nearby.
func findUnguardedDriverConstructionAnyFunc(file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			if pkg, sel, ok := egressIdentSel(e.Fun); ok && driverConstructionSelectors[sel] &&
				(pkg == "mongo" || pkg == "redis") {
				found = append(found, pkg+"."+sel+"(...)")
			}
		case *ast.CompositeLit:
			if sel, ok := e.Type.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" && sel.Sel.Name == "Client" {
					found = append(found, "http.Client{...}")
				}
			}
		}
		return true
	})
	return found
}
