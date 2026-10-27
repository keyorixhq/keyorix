package http

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// AIRGAP-WEBUI-1 item 3. Air-gapped and pilot installs serve the whole web UI and
// /docs from the binary, so no page the server hands out may name a third-party
// host: it would fail offline and send the operator's browser to someone else
// from an authenticated API host (swagger.go loaded swagger-ui from unpkg.com).
//
// TestAirgapServedMarkupNamesNoExternalHost scans, for http(s):// URLs and
// protocol-relative //host references to hosts outside externalHostAllowlist:
//   - every Go string literal under server/http (non-test) that is markup (an
//     HTML document or fragment, or CSS with @import/url()), found by go/ast;
//   - every .html .htm .css .svg file under server/http, server/webui/dist,
//     web/public and web/dist (when built), plus web/index.html and the CSS in
//     web/src.
//
// It reports each finding as file:line.
//
// What it does NOT cover (so a green run is not "the UI makes no external request"):
//   - JavaScript, including the Vite bundle in dist/assets and the vendored
//     swagger-ui bundle: a runtime fetch() or import() of a third-party URL is
//     invisible to it. The vendored bundle is pinned byte-for-byte instead
//     (handlers.TestSwaggerUIVendoredFilesArePinned) and the served /swagger/ page
//     is checked by TestSwaggerPage_NoExternalHost;
//   - Go string literals that are not markup (a URL in a redirect, a CORS default,
//     an SSO endpoint is a server-side or configured value, not something a
//     browser loads from a page), and a URL split across concatenated literals or
//     built with fmt.Sprintf from a variable host;
//   - markup generated outside server/http (server/middleware, internal/*);
//   - CSS inside a .html <style> block is scanned as part of the .html file, but
//     a CSS file is only scanned for http(s) and protocol-relative URLs, not for
//     bare relative ones (those are own-origin by construction).

// externalHostAllowlist is the set of hosts a served page may name, each with the
// reason. Own origin needs no entry: a relative reference has no host.
var externalHostAllowlist = map[string]string{
	"www.w3.org": "XML/SVG/XHTML namespace URI (xmlns=...): an identifier, never fetched",
}

type hostFinding struct {
	file string
	line int
	url  string
}

func (f hostFinding) String() string {
	return fmt.Sprintf("%s:%d: %s names a host outside the air-gap allowlist", f.file, f.line, f.url)
}

var (
	// An absolute http(s) URL, or a protocol-relative one in an attribute / url().
	absURLRe = regexp.MustCompile(`(?i)\bhttps?://([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
	relURLRe = regexp.MustCompile(`(?i)(?:\b(?:src|href|action|poster|data)\s*=\s*|\burl\(\s*|@import\s+)["']?\s*//([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
	// A Go string literal is "markup" when it looks like something a browser parses.
	markupRe = regexp.MustCompile(`(?i)<!doctype|<(?:html|head|body|script|link|style|img|iframe|form|meta|svg|a\s)\b|@import|\burl\(`)
)

// scanExternalHosts returns the URLs in text whose host is not allowlisted, with
// the line of each (firstLine is the line text starts on).
func scanExternalHosts(file, text string, firstLine int, allow map[string]string) []hostFinding {
	var out []hostFinding
	for _, re := range []*regexp.Regexp{absURLRe, relURLRe} {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			host := strings.ToLower(text[m[2]:m[3]])
			if _, ok := allow[host]; ok {
				continue
			}
			end := m[1]
			for end < len(text) && !strings.ContainsRune(" \t\r\n\"'`)<>", rune(text[end])) {
				end++
			}
			out = append(out, hostFinding{
				file: file,
				line: firstLine + strings.Count(text[:m[0]], "\n"),
				url:  text[m[0]:end],
			})
		}
	}
	return out
}

// scanGoMarkupLiterals scans the markup string literals of one Go source file.
// It returns the findings and how many markup literals it examined.
func scanGoMarkupLiterals(file string, src []byte, allow map[string]string) ([]hostFinding, int) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return []hostFinding{{file: file, line: 1, url: "unparsable Go file: " + err.Error()}}, 0
	}
	var out []hostFinding
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		// The source text of the literal, not its unquoted value: its newlines
		// then map 1:1 onto source lines for a raw string.
		text := string(src[fset.Position(lit.Pos()).Offset:fset.Position(lit.End()).Offset])
		if !markupRe.MatchString(text) {
			return true
		}
		n++
		out = append(out, scanExternalHosts(file, text, fset.Position(lit.Pos()).Line, allow)...)
		return true
	})
	return out, n
}

// --- the scanner itself: red on a bad page, green on a good one ---------------

func TestScanExternalHosts_CatchesAndAllows(t *testing.T) {
	bad := `<!DOCTYPE html>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
<script src="//cdn.example.com/x.js"></script>
<style>@import url(https://fonts.googleapis.com/css?family=Inter);</style>`
	got := scanExternalHosts("bad.html", bad, 10, externalHostAllowlist)
	var lines []int
	for _, f := range got {
		lines = append(lines, f.line)
	}
	assert.ElementsMatch(t, []int{11, 12, 13}, lines, "findings: %v", got)
	assert.Contains(t, got[0].String(), "bad.html:")

	good := `<!DOCTYPE html>
<svg xmlns="http://www.w3.org/2000/svg"></svg>
<link rel="stylesheet" href="/swagger/ui/swagger-ui.css" />
<script src="/assets/app.js"></script>
<a href="docs/page.html">relative</a>`
	assert.Empty(t, scanExternalHosts("good.html", good, 1, externalHostAllowlist))
}

func TestScanGoMarkupLiterals_UsesSourceLines(t *testing.T) {
	src := []byte("package x\n\nconst page = `<html>\n<body>\n<script src=\"https://evil.example/a.js\"></script>\n</body></html>`\n\nconst notMarkup = \"https://api.example.com/v1\"\n")
	got, n := scanGoMarkupLiterals("selftest-source", src, externalHostAllowlist)
	require.Equal(t, 1, n, "only the markup literal is examined")
	require.Len(t, got, 1)
	assert.Equal(t, 5, got[0].line)
	assert.Contains(t, got[0].url, "evil.example")
}

// --- the repo scan -------------------------------------------------------------

var scannedExts = map[string]bool{".html": true, ".htm": true, ".css": true, ".svg": true}

func TestAirgapServedMarkupNamesNoExternalHost(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()

	var findings []hostFinding
	files, goLits := 0, 0
	rel := func(p string) string {
		r, err := filepath.Rel(root, p)
		require.NoError(t, err)
		return filepath.ToSlash(r)
	}
	scanFile := func(p string) {
		data, err := os.ReadFile(p) // #nosec G304 -- walking the repo's own tree
		require.NoError(t, err)
		files++
		findings = append(findings, scanExternalHosts(rel(p), string(data), 1, externalHostAllowlist)...)
	}

	// Go markup literals under server/http, and the static files beside them.
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "server", "http"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch ext := strings.ToLower(filepath.Ext(p)); {
		case ext == ".go" && !strings.HasSuffix(p, "_test.go"):
			data, err := os.ReadFile(p) // #nosec G304 -- walking the repo's own tree
			require.NoError(t, err)
			files++
			fnd, n := scanGoMarkupLiterals(rel(p), data, externalHostAllowlist)
			goLits += n
			findings = append(findings, fnd...)
		case scannedExts[ext]:
			scanFile(p)
		}
		return nil
	}))

	// The SPA: the placeholder/real index in the embedded dist, the source index,
	// CSS in web/src, public assets, and a real build if one is present.
	for _, dir := range []string{
		filepath.Join(root, "server", "webui", "dist"),
		filepath.Join(root, "web", "public"),
		filepath.Join(root, "web", "src"),
		filepath.Join(root, "web", "dist"),
	} {
		if _, err := os.Stat(dir); err != nil {
			continue // web/dist exists only after a build
		}
		require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if scannedExts[strings.ToLower(filepath.Ext(p))] {
				scanFile(p)
			}
			return nil
		}))
	}
	scanFile(filepath.Join(root, "web", "index.html"))

	// Population tripwires: a moved directory must not turn this into a vacuous pass.
	assert.GreaterOrEqual(t, goLits, 1, "no markup string literal found under server/http: the swagger page moved or markupRe stopped matching")
	for _, must := range []string{"web/index.html", "server/webui/dist/index.html", "web/src/index.css"} {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(must)))
		require.NoError(t, err, "%s is a required scan target", must)
	}
	assert.GreaterOrEqual(t, files, 8, "scanned only %d files: a scan root moved", files)

	for _, f := range findings {
		g.Errorf("%s", f)
	}
}
