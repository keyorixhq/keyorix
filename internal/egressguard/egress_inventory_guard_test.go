// Package egressguard holds the guard behind docs/security/egress-inventory.md:
// the claim "this is every place Keyorix can open an outbound connection" is
// derived from the source and checked on every run, not asserted in prose.
//
// How the set of outbound sites is established (and why it is complete for the
// forms it knows):
//
//   - Every non-test .go file under the repository root is parsed with go/parser,
//     in the root module and in every nested module (cli/, operator/, migrate/,
//     devtools/, scripts/...). Build tags are ignored, so the airgap/noazure
//     variants are read too. Only _test.go files, testdata/, vendor/, web/ and
//     tool directories (.git, node_modules, .scratch, tmp, .claude) are skipped.
//   - A file is an outbound site when it uses one of three call forms, resolved
//     through the file's own import names (an alias such as `nethttp "net/http"`
//     is followed):
//     1. refForms: a reference to a function or variable that dials or sends
//     (http.Get, http.DefaultClient, net.Dial*, net.Lookup*, tls.Dial,
//     sql.Open, grpc.NewClient, gorm.Open, ...).
//     2. typeForms: construction of a client type, as a composite literal
//     (&http.Client{...}), new(T) or `var c T` (http.Client, http.Transport,
//     net.Dialer, net.Resolver, tls.Dialer, httputil.ReverseProxy). A type that
//     only appears in a parameter, field or return position is not a site.
//     3. clientImports: importing a package that exists only to talk to a remote
//     service (net/smtp, go-mail, the AWS/Azure/GCP SDK clients, database
//     drivers, go-redis, x/crypto/ssh, websocket libraries, an OTLP exporter,
//     client-go, controller-runtime). Importing is the site because those
//     libraries open the connection inside the call, with no stdlib symbol in
//     our own file.
//   - Each site must be covered by a row of docs/security/egress-allowlist.tsv
//     (a file, or a directory prefix ending in "/"), whose class must exist in
//     the table of docs/security/egress-inventory.md. Rows that cover no site,
//     and inventory classes with no row, fail too, so neither file can drift.
//   - The lists of call forms are themselves checked against go.mod:
//     TestEgressEveryDirectDependencyIsClassified requires every direct dependency
//     of every module in the repository to be classified in dependencyKinds as
//     "client" (and then recognised by the scanner) or "local: <reason>". The first
//     version of clientImports missed the MongoDB driver; this is what would have
//     caught it.
//   - Class DEV marks development and test tooling. TestEgressDevToolingIsNotImportedByShippedCode
//     proves the claim "not shipped": no file outside a DEV row imports a package
//     inside one, so the production dependency closure never reaches a DEV site.
//
// What it does NOT cover (a green run is not "Keyorix makes no other connection"):
//   - A connection made by a library through a package not listed in
//     clientImports, or through a function of a listed stdlib package that is not
//     in refForms. The lists are the reviewable assumption; extend them when a
//     new kind of client is adopted.
//   - What a subprocess does: the encryption key provider type "exec" and
//     `keyorix run` start a command that may itself use the network. The call
//     sites that start a process are checked by subprocess_guard_test.go; the
//     child's own connections are not.
//   - Browser-side requests: JavaScript in web/ and the vendored swagger UI. The
//     markup check lives in server/http/airgap_external_hosts_guard_test.go.
//   - Reflection, plugins and code generated at run time.
//   - That a site is actually reachable, on by default or off. The allowlist
//     records the class and the reason; the inventory states trigger, config key
//     and default, and those columns are reviewed prose.
//
// Rollout: report-only on its first day (docs/guard-rollout-contract.md,
// docs/guard-rollout.d/TestEgressSitesAreInventoried.tsv).
package egressguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const (
	allowlistRel = "docs/security/egress-allowlist.tsv"
	inventoryRel = "docs/security/egress-inventory.md"
	devClass     = "DEV"
)

// refForms: a reference to any of these symbols of the package is a site.
// The key is the import path; the package name must equal its last path element.
var refForms = map[string][]string{
	"net/http": {"Get", "Post", "PostForm", "Head", "DefaultClient", "DefaultTransport"},
	"net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix",
		"LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS",
		"LookupSRV", "LookupTXT", "LookupPort", "DefaultResolver"},
	"crypto/tls":                      {"Dial", "DialWithDialer"},
	"net/http/httputil":               {"NewSingleHostReverseProxy"},
	"database/sql":                    {"Open", "OpenDB"},
	"google.golang.org/grpc":          {"Dial", "DialContext", "NewClient"},
	"gorm.io/gorm":                    {"Open"},
	"golang.org/x/crypto/ssh":         {"Dial", "NewClientConn"},
	"github.com/jackc/pgx/v5":         {"Connect", "ConnectConfig"},
	"github.com/jackc/pgx/v5/pgxpool": {"New", "NewWithConfig", "ConnectConfig"},
	"github.com/jackc/pgx/v5/stdlib":  {"OpenDB", "RegisterConnConfig"},
	"github.com/crewjam/saml":         {"FetchMetadata"},
}

// typeForms: constructing a value of any of these types is a site.
var typeForms = map[string][]string{
	"net/http":          {"Client", "Transport"},
	"net":               {"Dialer", "Resolver"},
	"crypto/tls":        {"Dialer"},
	"net/http/httputil": {"ReverseProxy"},
}

// clientImports: importing a package whose path starts with one of these is a
// site. clientImportExcept removes packages that carry types only.
var clientImports = []string{
	"net/smtp",
	"net/rpc",
	"golang.org/x/oauth2", // Exchange/token fetch fall back to http.DefaultClient inside the library
	"golang.org/x/net/websocket",
	"github.com/gorilla/websocket",
	"nhooyr.io/websocket",
	"github.com/coder/websocket",
	"github.com/wneessen/go-mail",
	"github.com/aws/aws-sdk-go-v2/config",
	"github.com/aws/aws-sdk-go-v2/service/",
	"github.com/aws/aws-sdk-go-v2/feature/",
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity",
	"github.com/Azure/azure-sdk-for-go/sdk/security/",
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/",
	"github.com/Azure/azure-sdk-for-go/sdk/storage/",
	"cloud.google.com/go/",
	"google.golang.org/api/",
	"github.com/hashicorp/vault/api",
	"github.com/lib/pq",
	"github.com/go-sql-driver/mysql",
	"github.com/redis/go-redis/",
	"github.com/go-redis/redis",
	"go.mongodb.org/mongo-driver",
	"github.com/aws/aws-sdk-go-v2/credentials", // ec2rolecreds, ssocreds, stscreds, endpointcreds fetch over HTTP
	"github.com/keyorixhq/keyorix-sdks/",       // the Keyorix client SDKs
	"go.opentelemetry.io/otel/exporters/",
	"github.com/getsentry/",
	"github.com/prometheus/client_golang/prometheus/push",
	"k8s.io/client-go/",
	"sigs.k8s.io/controller-runtime",
}

var clientImportExcept = map[string]bool{
	"google.golang.org/api/option":   true,
	"google.golang.org/api/iterator": true,
}

// An import path whose last element is "types" (aws service types, azure models)
// or "bson" (mongo encoding) carries data types only.
func importIsClient(p string) bool {
	if clientImportExcept[p] || path.Base(p) == "types" || path.Base(p) == "bson" {
		return false
	}
	// A prefix ending in "/" matches every package below it; any other prefix
	// matches that package and the ones below it, never a longer sibling name.
	return slices.ContainsFunc(clientImports, func(pre string) bool {
		if strings.HasSuffix(pre, "/") {
			return strings.HasPrefix(p, pre)
		}
		return p == pre || strings.HasPrefix(p, pre+"/")
	})
}

// site is one place a file can open an outbound connection.
type site struct {
	File string // slash-separated, relative to the repository root
	Line int
	Form string // e.g. "net/http.Client{}", "import github.com/wneessen/go-mail"
}

// skipAnywhere are directory names the walk never enters; skipAtRoot only the
// ones directly under the repository root (web/ is the JS front end, tmp/ and
// .scratch/ are session scratch space, but internal/.../web is Go).
var (
	skipAnywhere = map[string]bool{".git": true, "node_modules": true, "vendor": true, "testdata": true}
	skipAtRoot   = map[string]bool{"web": true, "tmp": true, ".scratch": true, ".claude": true}
)

// skipDir reports whether the walk skips directory p (a path under root).
func skipDir(root, p string) bool {
	name := filepath.Base(p)
	if skipAnywhere[name] {
		return true
	}
	if filepath.Dir(p) == root {
		return skipAtRoot[name] || strings.HasPrefix(name, ".redproof-") || strings.HasPrefix(name, ".gopath")
	}
	return false
}

// localNames maps the local name of each import in f to its path. A blank or dot
// import has no usable name here and is ignored (its path is still checked as an
// import).
func localNames(f *ast.File) map[string]string {
	names := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if len(name) > 1 && name[0] == 'v' && isDigits(name[1:]) { // /v5 -> previous element
			name = path.Base(path.Dir(p))
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		names[name] = p
	}
	return names
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// selector returns (import path, symbol) for pkg.Sym when pkg is an imported name.
func selector(names map[string]string, e ast.Expr) (string, string, bool) {
	se, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	id, ok := se.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	p, ok := names[id.Name]
	if !ok {
		return "", "", false
	}
	return p, se.Sel.Name, true
}

// scanSource returns the outbound sites of one parsed file.
func scanSource(fset *token.FileSet, f *ast.File, rel string) []site {
	names := localNames(f)
	var out []site
	add := func(pos token.Pos, form string) {
		out = append(out, site{File: rel, Line: fset.Position(pos).Line, Form: form})
	}
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && importIsClient(p) {
			add(imp.Pos(), "import "+p)
		}
	}
	typeHit := func(e ast.Expr) (string, bool) {
		p, sym, ok := selector(names, e)
		if ok && slices.Contains(typeForms[p], sym) {
			return p + "." + sym, true
		}
		return "", false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if p, sym, ok := selector(names, x); ok && slices.Contains(refForms[p], sym) {
				add(x.Pos(), p+"."+sym)
			}
		case *ast.CompositeLit:
			if form, ok := typeHit(x.Type); ok {
				add(x.Pos(), form+"{}")
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if form, ok := typeHit(x.Args[0]); ok {
					add(x.Pos(), "new("+form+")")
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil {
				if form, ok := typeHit(x.Type); ok {
					add(x.Pos(), "var "+form)
				}
			}
		}
		return true
	})
	return out
}

// scanTree parses every non-test Go file under root.
func scanTree(root string) ([]site, error) {
	var all []site
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		all = append(all, scanSource(fset, f, filepath.ToSlash(rel))...)
		return nil
	})
	return all, err
}

// allowRow is one row of docs/security/egress-allowlist.tsv.
type allowRow struct {
	Path   string // a file, or a directory prefix ending in "/"
	Class  string // an id of the inventory table, or DEV
	Reason string
}

func (r allowRow) covers(file string) bool {
	if strings.HasSuffix(r.Path, "/") {
		return strings.HasPrefix(file, r.Path)
	}
	return file == r.Path
}

var classRe = regexp.MustCompile(`^(E\d\d|DEV)$`)

func parseAllowlist(data string) ([]allowRow, error) {
	var rows []allowRow
	seen := map[string]bool{}
	for i, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("%s:%d: want 3 tab-separated columns (path, class, reason), got %d", allowlistRel, i+1, len(f))
		}
		r := allowRow{Path: f[0], Class: f[1], Reason: strings.TrimSpace(f[2])}
		switch {
		case r.Path == "" || strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, ".."):
			return nil, fmt.Errorf("%s:%d: path %q must be relative to the repository root", allowlistRel, i+1, r.Path)
		case !classRe.MatchString(r.Class):
			return nil, fmt.Errorf("%s:%d: class %q must be E<nn> or %s", allowlistRel, i+1, r.Class, devClass)
		case r.Reason == "":
			return nil, fmt.Errorf("%s:%d: row for %s has no reason", allowlistRel, i+1, r.Path)
		case seen[r.Path]:
			return nil, fmt.Errorf("%s:%d: duplicate row for %s", allowlistRel, i+1, r.Path)
		}
		seen[r.Path] = true
		rows = append(rows, r)
	}
	return rows, nil
}

var inventoryClassRe = regexp.MustCompile(`(?m)^\|\s*(E\d\d|DEV)\s*\|`)

// inventoryClasses returns the class ids of the table in the inventory document.
func inventoryClasses(doc string) map[string]bool {
	ids := map[string]bool{}
	for _, m := range inventoryClassRe.FindAllStringSubmatch(doc, -1) {
		ids[m[1]] = true
	}
	return ids
}

// checkInventory returns one message per violation: a site no row covers, a row
// that covers no site, a class missing from the inventory, an inventory class
// with no row.
func checkInventory(sites []site, rows []allowRow, classes map[string]bool) []string {
	var msgs []string
	siteFiles := map[string]bool{}
	for _, s := range sites {
		siteFiles[s.File] = true
	}
	// One message per uncovered file, naming its first site and every form.
	forms := map[string][]string{}
	first := map[string]int{}
	for _, s := range sites {
		if _, ok := first[s.File]; !ok || s.Line < first[s.File] {
			first[s.File] = s.Line
		}
		if !slices.Contains(forms[s.File], s.Form) {
			forms[s.File] = append(forms[s.File], s.Form)
		}
	}
	var files []string
	for f := range siteFiles {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		covered := false
		for _, r := range rows {
			if r.covers(f) {
				covered = true
				break
			}
		}
		if !covered {
			sort.Strings(forms[f])
			msgs = append(msgs, fmt.Sprintf("%s:%d creates an outbound connection (%s) and has no row in %s: add the file with a class and a reason, and a row to %s if it is a new destination class",
				f, first[f], strings.Join(forms[f], ", "), allowlistRel, inventoryRel))
		}
	}
	used := map[string]bool{}
	for _, r := range rows {
		hit := false
		for f := range siteFiles {
			if r.covers(f) {
				hit = true
				break
			}
		}
		if !hit {
			msgs = append(msgs, fmt.Sprintf("%s: row %q (%s) covers no outbound site any more: delete it", allowlistRel, r.Path, r.Class))
		}
		used[r.Class] = true
		if !classes[r.Class] {
			msgs = append(msgs, fmt.Sprintf("%s: row %q names class %s, which is not in the table of %s", allowlistRel, r.Path, r.Class, inventoryRel))
		}
	}
	var ids []string
	for id := range classes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !used[id] {
			msgs = append(msgs, fmt.Sprintf("%s: class %s is in the inventory table but no allowlist row names it: the row is a claim with no code behind it", inventoryRel, id))
		}
	}
	return msgs
}

// modulePaths maps each go.mod directory (slash, relative to root, "" = root) to
// its module path.
func modulePaths(root string) (map[string]string, error) {
	mods := map[string]string{}
	re := regexp.MustCompile(`(?m)^module\s+(\S+)`)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		data, err := os.ReadFile(p) // #nosec G304 -- walked under the repository root
		if err != nil {
			return err
		}
		m := re.FindSubmatch(data)
		if m == nil {
			return nil
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		if rel == "." {
			rel = ""
		}
		mods[filepath.ToSlash(rel)] = string(m[1])
		return nil
	})
	return mods, err
}

// importDir resolves an import path to a repository directory, or "" for a
// package outside the repository. The longest matching module path wins.
func importDir(mods map[string]string, imp string) string {
	best, bestDir := "", ""
	for dir, mp := range mods {
		if (imp == mp || strings.HasPrefix(imp, mp+"/")) && len(mp) > len(best) {
			best, bestDir = mp, dir
		}
	}
	if best == "" {
		return ""
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(imp, best), "/")
	return path.Join(bestDir, rest)
}

// devImports returns "file: imports <path>" for every non-test file outside a DEV
// row that imports a package inside one.
func devImports(root string, rows []allowRow) ([]string, error) {
	mods, err := modulePaths(root)
	if err != nil {
		return nil, err
	}
	var dev []allowRow
	for _, r := range rows {
		if r.Class == devClass {
			dev = append(dev, r)
		}
	}
	inDev := func(rel string) bool {
		for _, r := range dev {
			if r.covers(rel) || r.covers(rel+"/") {
				return true
			}
		}
		return false
	}
	var msgs []string
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		relOS, _ := filepath.Rel(root, p)
		rel := filepath.ToSlash(relOS)
		if inDev(rel) {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		for _, imp := range f.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if dir := importDir(mods, ip); dir != "" && inDev(dir) {
				msgs = append(msgs, fmt.Sprintf("%s:%d imports %s, which is development tooling (class %s in %s); a shipped package must not depend on it",
					rel, fset.Position(imp.Pos()).Line, ip, devClass, allowlistRel))
			}
		}
		return nil
	})
	sort.Strings(msgs)
	return msgs, err
}

func loadRepoFiles(t testing.TB) (root string, rows []allowRow, classes map[string]bool) {
	t.Helper()
	root = srcpath.RepoRoot()
	data, err := os.ReadFile(filepath.Join(root, allowlistRel)) // #nosec G304 -- fixed path under the repository root
	require.NoError(t, err, "the allowlist is missing")
	rows, err = parseAllowlist(string(data))
	require.NoError(t, err)
	doc, err := os.ReadFile(filepath.Join(root, inventoryRel)) // #nosec G304 -- fixed path under the repository root
	require.NoError(t, err, "the inventory document is missing")
	return root, rows, inventoryClasses(string(doc))
}

// TestEgressSitesAreInventoried: every outbound site in the tree is covered by an
// allowlist row with a class and a reason, and the allowlist and the inventory
// table name the same classes.
func TestEgressSitesAreInventoried(t *testing.T) {
	g := guardrules.Rollout(t)
	root, rows, classes := loadRepoFiles(g)
	sites, err := scanTree(root)
	require.NoError(g, err)
	require.NotEmpty(g, sites, "the scan found no outbound site at all: the scanner is broken, not the tree clean")
	for _, m := range checkInventory(sites, rows, classes) {
		g.Errorf("%s", m)
	}
}

// TestEgressDevToolingIsNotImportedByShippedCode makes the DEV rows of the
// allowlist true: nothing outside them imports a package inside them.
func TestEgressDevToolingIsNotImportedByShippedCode(t *testing.T) {
	g := guardrules.Rollout(t)
	root, rows, _ := loadRepoFiles(g)
	msgs, err := devImports(root, rows)
	require.NoError(g, err)
	for _, m := range msgs {
		g.Errorf("%s", m)
	}
}

// ---- self-tests: the scanner and the checks against planted fixtures ----------

const fixtureHTTP = `package x

import (
	nethttp "net/http"
	"net"
)

func f() {
	_ = &nethttp.Client{}
	_, _ = net.Dial("tcp", "h:1")
}
`

func scanText(t *testing.T, rel, src string) []site {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	require.NoError(t, err)
	return scanSource(fset, f, rel)
}

func formsOf(sites []site) []string {
	var out []string
	for _, s := range sites {
		out = append(out, s.Form)
	}
	sort.Strings(out)
	return out
}

func TestEgressScanner_FindsEachCallForm(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"aliased composite literal and dial", fixtureHTTP, []string{"net.Dial", "net/http.Client{}"}},
		{"new(T)", `package x
import "net/http"
var _ = new(http.Transport)
`, []string{"new(net/http.Transport)"}},
		{"var T", `package x
import "net/http"
var c http.Client
`, []string{"var net/http.Client"}},
		{"default client", `package x
import "net/http"
func f() { _, _ = http.DefaultClient.Get("u") }
`, []string{"net/http.DefaultClient"}},
		{"package function", `package x
import "net/http"
func f() { _, _ = http.Get("u") }
`, []string{"net/http.Get"}},
		{"dns lookup", `package x
import "net"
func f() { _, _ = net.LookupHost("h") }
`, []string{"net.LookupHost"}},
		{"tls dial", `package x
import "crypto/tls"
func f() { _, _ = tls.Dial("tcp", "h:1", nil) }
`, []string{"crypto/tls.Dial"}},
		{"sql open", `package x
import "database/sql"
func f() { _, _ = sql.Open("pgx", "d") }
`, []string{"database/sql.Open"}},
		{"versioned import name", `package x
import "google.golang.org/grpc"
func f() { _, _ = grpc.NewClient("h") }
`, []string{"google.golang.org/grpc.NewClient"}},
		{"client-only import", `package x
import "github.com/redis/go-redis/v9"
var _ = redis.NewClient
`, []string{"import github.com/redis/go-redis/v9"}},
		{"oauth2 import (library-default client)", `package x
import "golang.org/x/oauth2"
var _ oauth2.Config
`, []string{"import golang.org/x/oauth2"}},
		{"pgxpool constructor", `package x
import "github.com/jackc/pgx/v5/pgxpool"
func f() { _, _ = pgxpool.New(nil, "d") }
`, []string{"github.com/jackc/pgx/v5/pgxpool.New"}},
		{"pgx connect, name from a versioned path", `package x
import "github.com/jackc/pgx/v5"
func f() { _, _ = pgx.Connect(nil, "d") }
`, []string{"github.com/jackc/pgx/v5.Connect"}},
		{"ssh dial", `package x
import "golang.org/x/crypto/ssh"
func f() { _, _ = ssh.Dial("tcp", "h:22", nil) }
`, []string{"golang.org/x/crypto/ssh.Dial"}},
		{"saml metadata fetch (aliased import)", `package x
import csaml "github.com/crewjam/saml"
func f() { _, _ = csaml.FetchMetadata(nil, nil, nil) }
`, []string{"github.com/crewjam/saml.FetchMetadata"}},
		{"smtp import", `package x
import "net/smtp"
var _ = smtp.PlainAuth
`, []string{"import net/smtp"}},
		{"otlp exporter import", `package x
import _ "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
`, []string{"import go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, formsOf(scanText(t, "x.go", c.src)))
		})
	}
}

func TestEgressScanner_SparesWhatIsNotAConnection(t *testing.T) {
	for name, src := range map[string]string{
		"client only in a parameter":  "package x\nimport \"net/http\"\nfunc f(c *http.Client) {}\n",
		"client only in a field":      "package x\nimport \"net/http\"\ntype T struct{ C *http.Client }\n",
		"request without a client":    "package x\nimport \"net/http\"\nfunc f() { _, _ = http.NewRequest(\"GET\", \"u\", nil) }\n",
		"status constants":            "package x\nimport \"net/http\"\nvar _ = http.StatusOK\n",
		"a local named http":          "package x\ntype h struct{ Client int }\nfunc f() { http := h{}; _ = http.Client }\n",
		"types-only aws import":       "package x\nimport _ \"github.com/aws/aws-sdk-go-v2/service/kms/types\"\n",
		"gcp option import":           "package x\nimport _ \"google.golang.org/api/option\"\n",
		"listener is inbound":         "package x\nimport \"net\"\nfunc f() { _, _ = net.Listen(\"tcp\", \":0\") }\n",
		"unrelated import path match": "package x\nimport _ \"github.com/redis/go-redismock\"\n",
		"pgconn error types only":     "package x\nimport \"github.com/jackc/pgx/v5/pgconn\"\nvar _ *pgconn.PgError\n",
		"ssh key parsing only":        "package x\nimport \"golang.org/x/crypto/ssh\"\nfunc f() { _, _, _, _, _ = ssh.ParseAuthorizedKey(nil) }\n",
		"saml without fetch":          "package x\nimport csaml \"github.com/crewjam/saml\"\nvar _ csaml.EntityDescriptor\n",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, scanText(t, "x.go", src))
		})
	}
}

func TestEgressCheck_RedOnPlantedSiteGreenWhenListed(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("go.mod", "module example.test/m\n")
	write("srv/ok.go", "package srv\n")
	write("srv/ok_test.go", fixtureHTTP) // test files are not sites
	write("testdata/x.go", fixtureHTTP)  // neither is testdata
	classes := map[string]bool{"E01": true}
	rows := []allowRow{{Path: "srv/hook.go", Class: "E01", Reason: "operator webhook"}}

	// Red 1: nothing planted, but the row points at a file with no site.
	sites, err := scanTree(root)
	require.NoError(t, err)
	assert.Empty(t, sites)
	msgs := checkInventory(sites, rows, classes)
	assert.Contains(t, strings.Join(msgs, "\n"), "covers no outbound site any more")

	// Red 2: plant an unlisted client.
	write("srv/planted.go", fixtureHTTP)
	sites, err = scanTree(root)
	require.NoError(t, err)
	msgs = checkInventory(sites, nil, classes)
	require.Len(t, msgs, 2, "the planted file and the unused class: %v", msgs)
	assert.Contains(t, msgs[0], "srv/planted.go:9 creates an outbound connection")
	assert.Contains(t, msgs[0], "net/http.Client{}")
	assert.Contains(t, msgs[1], "class E01 is in the inventory table but no allowlist row names it")

	// Green: the same tree with a row for the file and its class.
	rows = []allowRow{{Path: "srv/planted.go", Class: "E01", Reason: "operator webhook"}}
	assert.Empty(t, checkInventory(sites, rows, classes))

	// A directory prefix covers a file below it; an unknown class is refused.
	rows = []allowRow{{Path: "srv/", Class: "E02", Reason: "x"}}
	msgs = checkInventory(sites, rows, classes)
	assert.Contains(t, strings.Join(msgs, "\n"), "class E02, which is not in the table")
}

func TestEgressAllowlist_ParseRejectsBadRows(t *testing.T) {
	good := "a/b.go\tE01\tbecause\n"
	rows, err := parseAllowlist("# c\n\n" + good)
	require.NoError(t, err)
	assert.Equal(t, []allowRow{{Path: "a/b.go", Class: "E01", Reason: "because"}}, rows)
	for name, in := range map[string]string{
		"two columns":       "a/b.go\tE01\n",
		"empty reason":      "a/b.go\tE01\t \n",
		"unknown class":     "a/b.go\tX1\tr\n",
		"absolute path":     "/a/b.go\tE01\tr\n",
		"parent escape":     "../a.go\tE01\tr\n",
		"duplicate row":     good + good,
		"lowercase class":   "a/b.go\te01\tr\n",
		"three-digit class": "a/b.go\tE001\tr\n",
	} {
		_, err := parseAllowlist(in)
		assert.Error(t, err, name)
	}
}

func TestEgressInventory_ClassesComeFromTheTable(t *testing.T) {
	doc := "| ID | what |\n|---|---|\n| E01 | a |\n| E12 | b |\n| DEV | c |\nE03 in prose is not a row\n"
	assert.Equal(t, map[string]bool{"E01": true, "E12": true, "DEV": true}, inventoryClasses(doc))
}

func TestEgressDevImports_RedWhenShippedCodeImportsDevTooling(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("go.mod", "module example.test/m\n")
	write("cli/go.mod", "module example.test/m/cli\n")
	write("scripts/tool/tool.go", "package tool\n")
	write("srv/prod.go", "package srv\nimport _ \"example.test/m/scripts/tool\"\n")
	write("scripts/tool/user.go", "package tool\nimport _ \"example.test/m/scripts/tool\"\n") // dev -> dev is fine
	write("cli/cmd.go", "package cli\nimport _ \"example.test/m/scripts/tool\"\n")
	rows := []allowRow{{Path: "scripts/", Class: devClass, Reason: "dev tooling"}}
	msgs, err := devImports(root, rows)
	require.NoError(t, err)
	require.Len(t, msgs, 2, "%v", msgs)
	assert.Contains(t, msgs[0], "cli/cmd.go:2 imports example.test/m/scripts/tool")
	assert.Contains(t, msgs[1], "srv/prod.go:2 imports example.test/m/scripts/tool")

	// Green: shipped code imports only shipped code.
	write("srv/prod.go", "package srv\n")
	write("cli/cmd.go", "package cli\n")
	msgs, err = devImports(root, rows)
	require.NoError(t, err)
	assert.Empty(t, msgs)
}

func TestEgressImportDir_LongestModuleWins(t *testing.T) {
	mods := map[string]string{"": "ex.test/m", "cli": "ex.test/m/cli"}
	assert.Equal(t, "internal/x", importDir(mods, "ex.test/m/internal/x"))
	assert.Equal(t, "cli/cmd", importDir(mods, "ex.test/m/cli/cmd"))
	assert.Equal(t, "cli", importDir(mods, "ex.test/m/cli"))
	assert.Equal(t, "", importDir(mods, "other.test/z"))
}

// ---- completeness of the import list: every direct dependency is classified -----

// dependencyKinds classifies every direct module dependency of every go.mod in the
// repository: "client" (the module can open a connection and the scanner knows it:
// an import prefix in clientImports or a symbol in refForms) or "local: <why it
// opens none>". This is what makes the lists above checkable instead of remembered:
// the Mongo driver was missing from clientImports until this table was written, and
// a new direct dependency now fails TestEgressEveryDirectDependencyIsClassified
// until someone decides which kind it is.
var dependencyKinds = map[string]string{
	"cloud.google.com/go/kms":                                           "client",
	"cloud.google.com/go/secretmanager":                                 "client",
	"filippo.io/age":                                                    "local: file encryption of the recovery key and backups",
	"github.com/Azure/azure-sdk-for-go/sdk/azcore":                      "local: pipeline and policy types; the Azure clients are azidentity and security/*",
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity":                  "client",
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys":    "client",
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets": "client",
	"github.com/anishathalye/porcupine":                                 "local: linearizability checker for test tooling",
	"github.com/aws/aws-sdk-go-v2":                                      "local: core types; the clients are config, credentials and service/*",
	"github.com/aws/aws-sdk-go-v2/config":                               "client",
	"github.com/aws/aws-sdk-go-v2/credentials":                          "client",
	"github.com/aws/aws-sdk-go-v2/service/iam":                          "client",
	"github.com/aws/aws-sdk-go-v2/service/kms":                          "client",
	"github.com/aws/aws-sdk-go-v2/service/s3":                           "client",
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager":               "client",
	"github.com/aws/aws-sdk-go-v2/service/sts":                          "client",
	"github.com/beevik/etree":                                           "local: XML tree",
	"github.com/crewjam/saml":                                           "client",
	"github.com/digitorus/pkcs7":                                        "local: parses and verifies PKCS#7",
	"github.com/digitorus/timestamp":                                    "local: builds and parses RFC 3161 messages; the request is sent by internal/notary with an http.Client",
	"github.com/getkin/kin-openapi":                                     "local: OpenAPI document handling",
	"github.com/go-chi/chi/v5":                                          "local: HTTP router for inbound requests",
	"github.com/go-chi/cors":                                            "local: CORS middleware for inbound requests",
	"github.com/go-logr/logr":                                           "local: logging interface",
	"github.com/go-sql-driver/mysql":                                    "client",
	"github.com/go-webauthn/webauthn":                                   "local: verifies WebAuthn ceremonies, no network",
	"github.com/golang-jwt/jwt/v5":                                      "local: parses and verifies JWTs, keys are supplied by the caller",
	"github.com/google/go-tpm":                                          "local: talks to the host TPM device",
	"github.com/google/go-tpm-tools":                                    "local: TPM 2.0 helpers",
	"github.com/googleapis/gax-go/v2":                                   "local: retry and call options for the GCP clients",
	"github.com/jackc/pgx/v5":                                           "client",
	"github.com/keyorixhq/keyorix-sdks/go":                              "client",
	"github.com/mattermost/xml-roundtrip-validator":                     "local: XML validation",
	"github.com/nicksnyder/go-i18n/v2":                                  "local: message catalogs",
	"github.com/oapi-codegen/runtime":                                   "local: request-building helpers of a generated client; the client's http.Client is a flagged site",
	"github.com/pquerna/otp":                                            "local: TOTP generation and validation",
	"github.com/prometheus/client_golang":                               "local: metrics registry and the inbound /metrics handler; the push gateway package is in clientImports",
	"github.com/prometheus/client_model":                                "local: metric data model",
	"github.com/redis/go-redis/v9":                                      "client",
	"github.com/russellhaering/goxmldsig":                               "local: XML signatures",
	"github.com/santhosh-tekuri/jsonschema/v6":                          "local: JSON schema validation",
	"github.com/shirou/gopsutil/v4":                                     "local: reads local CPU and disk statistics",
	"github.com/spf13/cobra":                                            "local: CLI framework",
	"github.com/spf13/pflag":                                            "local: flag parsing",
	"github.com/stretchr/testify":                                       "local: test assertions",
	"github.com/wneessen/go-mail":                                       "client",
	"go.mongodb.org/mongo-driver/v2":                                    "client",
	"golang.org/x/crypto":                                               "client", // the ssh package's Dial and NewClientConn are in refForms
	"golang.org/x/net":                                                  "client", // the websocket package is in clientImports
	"golang.org/x/oauth2":                                               "client",
	"golang.org/x/sync":                                                 "local: concurrency helpers",
	"golang.org/x/sys":                                                  "local: system calls",
	"golang.org/x/term":                                                 "local: terminal handling",
	"golang.org/x/text":                                                 "local: text handling",
	"golang.org/x/time":                                                 "local: rate limiting",
	"golang.org/x/tools":                                                "local: static-analysis tooling",
	"google.golang.org/api":                                             "client",
	"google.golang.org/genproto/googleapis/rpc":                         "local: protobuf types",
	"google.golang.org/grpc":                                            "client",
	"google.golang.org/protobuf":                                        "local: protobuf runtime",
	"gopkg.in/yaml.v3":                                                  "local: YAML parsing",
	"gorm.io/driver/postgres":                                           "local: a gorm dialector; the connection is opened by gorm.Open, which is in refForms",
	"gorm.io/driver/sqlite":                                             "local: a gorm dialector for a local SQLite file",
	"gorm.io/gorm":                                                      "client",
	"k8s.io/api":                                                        "local: Kubernetes object types",
	"k8s.io/apimachinery":                                               "local: Kubernetes object machinery",
	"k8s.io/client-go":                                                  "client",
	"modernc.org/sqlite":                                                "local: SQLite in the process, a local file",
	"sigs.k8s.io/controller-runtime":                                    "client",
	"sigs.k8s.io/yaml":                                                  "local: YAML parsing",
}

// detected reports whether the scanner would flag a file using module mod: an
// import prefix of clientImports or a symbol path of refForms lies on or under mod.
func detected(mod string) bool {
	overlaps := func(p string) bool {
		p = strings.TrimSuffix(p, "/")
		return p == mod || strings.HasPrefix(p, mod+"/") || strings.HasPrefix(mod, p+"/")
	}
	if slices.ContainsFunc(clientImports, overlaps) {
		return true
	}
	for p := range refForms {
		if overlaps(p) {
			return true
		}
	}
	return false
}

var (
	requireBlockRe  = regexp.MustCompile(`^require\s*\($`)
	requireLineRe   = regexp.MustCompile(`^\s*(\S+)\s+v\S+(\s*//.*)?$`)
	requireSingleRe = regexp.MustCompile(`^require\s+(\S+)\s+v\S+(\s*//.*)?$`)
)

// directRequires returns the module paths a go.mod requires without "// indirect".
func directRequires(goMod string) []string {
	var out []string
	inBlock := false
	for line := range strings.SplitSeq(goMod, "\n") {
		line = strings.TrimRight(line, " \t\r")
		switch {
		case requireBlockRe.MatchString(line):
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			if m := requireLineRe.FindStringSubmatch(line); m != nil && !strings.Contains(m[2], "indirect") {
				out = append(out, m[1])
			}
		default:
			if m := requireSingleRe.FindStringSubmatch(line); m != nil && !strings.Contains(m[2], "indirect") {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// checkDependencies returns one message per direct dependency that is unclassified,
// or classified "client" while the scanner would not recognise it, or "local" with
// no reason. own lists module paths of this repository (never a finding).
func checkDependencies(deps map[string]string, kinds map[string]string, own []string) []string {
	var msgs []string
	var names []string
	for d := range deps {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		if slices.ContainsFunc(own, func(o string) bool { return d == o || strings.HasPrefix(d, o+"/") }) {
			continue
		}
		kind, ok := kinds[d]
		switch {
		case !ok:
			msgs = append(msgs, fmt.Sprintf("%s (direct dependency in %s) is not classified: decide whether it can open a connection. If it can, add its import path to clientImports (or its dialing functions to refForms) in this file and a row for each file that uses it to %s, then add it to dependencyKinds as \"client\"; if it cannot, add it as \"local: <why>\"",
				d, deps[d], allowlistRel))
		case kind == "client" && !detected(d):
			msgs = append(msgs, fmt.Sprintf("%s is classified client, but neither clientImports nor refForms cover it: a file using it would not be flagged", d))
		case kind != "client" && (!strings.HasPrefix(kind, "local: ") || strings.TrimSpace(strings.TrimPrefix(kind, "local: ")) == ""):
			msgs = append(msgs, fmt.Sprintf("%s: class %q must be \"client\" or \"local: <reason>\"", d, kind))
		}
	}
	return msgs
}

// goModDeps returns module path -> the go.mod (relative) that requires it directly.
func goModDeps(root string) (map[string]string, []string, error) {
	deps := map[string]string{}
	var own []string
	mods, err := modulePaths(root)
	if err != nil {
		return nil, nil, err
	}
	var dirs []string
	for dir, mp := range mods {
		dirs = append(dirs, dir)
		own = append(own, mp)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		rel := path.Join(dir, "go.mod")
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- found by the walk above
		if err != nil {
			return nil, nil, err
		}
		for _, d := range directRequires(string(data)) {
			if _, seen := deps[d]; !seen {
				deps[d] = rel
			}
		}
	}
	return deps, own, nil
}

// TestEgressEveryDirectDependencyIsClassified: a new client library cannot enter any
// module of the repository without a decision recorded in dependencyKinds.
func TestEgressEveryDirectDependencyIsClassified(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	deps, own, err := goModDeps(root)
	require.NoError(g, err)
	require.NotEmpty(g, deps)
	// A module path equal to or below one of the repository's own (the replaced
	// root module and its cli/operator/migrate children) is not a dependency here;
	// keyorix-sdks is a separate repository and is classified.
	for _, m := range checkDependencies(deps, dependencyKinds, own) {
		g.Errorf("%s", m)
	}
}

func TestEgressDirectRequires_ParsesBlocksAndSingleLines(t *testing.T) {
	mod := "module x\n\ngo 1.27\n\nrequire (\n\ta.test/one v1.0.0\n\tb.test/two v2.0.0 // indirect\n\tc.test/three/v3 v3.1.0 // pinned\n)\n\nrequire d.test/four v0.1.0\nrequire e.test/five v0.1.0 // indirect\nreplace f.test/six => ../six\ntool g.test/seven\n"
	assert.Equal(t, []string{"a.test/one", "c.test/three/v3", "d.test/four"}, directRequires(mod))
}

func TestEgressCheckDependencies_RedForUnclassifiedGreenWhenClassified(t *testing.T) {
	deps := map[string]string{"x.test/newclient": "go.mod", "x.test/leaf": "go.mod", "self.test/m/cli": "cli/go.mod"}
	own := []string{"self.test/m"}
	// Red: neither dependency is classified.
	msgs := checkDependencies(deps, map[string]string{}, own)
	require.Len(t, msgs, 2, "%v", msgs)
	assert.Contains(t, msgs[0], "x.test/leaf (direct dependency in go.mod) is not classified")
	assert.Contains(t, msgs[1], "x.test/newclient")
	// Red: "client" that the scanner would not recognise, and a "local" with no reason.
	msgs = checkDependencies(deps, map[string]string{"x.test/newclient": "client", "x.test/leaf": "local: "}, own)
	require.Len(t, msgs, 2, "%v", msgs)
	assert.Contains(t, msgs[0], "must be \"client\" or \"local: <reason>\"")
	assert.Contains(t, msgs[1], "neither clientImports nor refForms cover it")
	// Green: a known client module and a reasoned local one.
	deps = map[string]string{"go.mongodb.org/mongo-driver/v2": "go.mod", "x.test/leaf": "go.mod"}
	assert.Empty(t, checkDependencies(deps, map[string]string{"go.mongodb.org/mongo-driver/v2": "client", "x.test/leaf": "local: pure parsing"}, nil))
}

func TestEgressDetected_ModulesFollowTheListsNotTheTable(t *testing.T) {
	assert.True(t, detected("go.mongodb.org/mongo-driver/v2"))
	assert.True(t, detected("github.com/jackc/pgx/v5"))
	assert.True(t, detected("golang.org/x/crypto"), "ssh.Dial is in refForms")
	assert.True(t, detected("cloud.google.com/go/kms"))
	assert.False(t, detected("github.com/spf13/cobra"))
}

func TestEgressDependencyTable_ClientEntriesAreAllDetected(t *testing.T) {
	var bad []string
	for d, kind := range dependencyKinds {
		if kind == "client" && !detected(d) {
			bad = append(bad, d)
		}
	}
	sort.Strings(bad)
	assert.Empty(t, bad, "classified client but not recognised by the scanner")
}
