package docsdrift

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// DOCS-PATHREF-1: migrations/README.md named internal/cli/migrate/migrate.go for
// weeks after SUBTRACT-202611 deleted it. links_test.go checks markdown links only;
// nothing read the backticked repo paths that pilot customers and auditors follow.
//
// What it reads: the inline code spans (single backticks, outside fenced blocks) of
// README.md, QUICK_START.md, SELF_HOSTING.md (docs/ or root), RELEASING.md,
// migrations/README.md (the file that started this) and every docs/**/*.md except the
// historical ones listed below. Each whitespace-separated word
// inside a span that starts with one of codePathPrefixes (optionally behind `./`) is a
// repo path and must exist in the working tree, which is HEAD in CI.
//
// Forms recognised, all normalised before the lookup:
//
//   - plain file or directory, with or without a trailing `/`;
//   - `path:LINE`, `path:LINE-LINE`, `path:LINE:COL`: the suffix is dropped, the line
//     is NOT checked (only that the file exists);
//   - `path#anchor`: the anchor is dropped and NOT checked;
//   - Go package wildcard `dir/...`: the directory must exist;
//   - glob `*` / `?` / `[..]`: at least one entry must match; `**` is treated as "any
//     depth", so only the directory before the first `**` segment must exist;
//   - `<placeholder>`: the segments before the first one containing `<` must exist
//     (`internal/<pkg>/x.go` needs `internal/`); `vX.Y.Z` counts as a placeholder;
//   - brace expansion `dir/f.{a,b}`: every expansion must exist;
//   - `path:TestName` and `dir.Symbol` (capitalised Go identifier): the symbol is
//     dropped and NOT checked; a trailing `(args)` or Go-regexp `$` is dropped too.
//
// What it does NOT read: fenced code blocks, URLs, paths after `--flag=`, a path that
// does not start with a listed prefix (`cmd/...`, `.github/...`, `operator/...`, a
// bare file name), double-backtick spans, files generated or gitignored at build time
// (list them in testdata/code_path_refs_exceptions.txt), and any claim about what the
// file contains.
//
// Excluded documents, because they are dated records (or designs written before the
// code exists) that legitimately cite files that were later deleted, renamed or not yet
// written: docs/adr-*, docs/design*, docs/specs/, docs/findings/, docs/triage/,
// docs/releases/v* (release notes cite changelog fragments that are deleted at release),
// the G80 campaign notes (docs/g80-*), docs/cli-split-*, docs/security-review-*,
// docs/cli-migration.md (its header says FROZEN), and any docs file whose name contains
// "report", "findings", "census", "sweep" or "measurement", or ends in "-design.md".
// Rewriting a sentence in them would falsify the record.
//
// Exceptions: testdata/code_path_refs_exceptions.txt, `path<TAB>reason` per line. An
// entry that no scanned document needs any more is itself an error, so the file cannot
// rot.
//
// Report-only on the first day (docs/guard-rollout.d/TestDocsCitedRepoPathsExist.tsv).

const codePathExceptions = "testdata/code_path_refs_exceptions.txt"

var (
	codePathPrefixes = []string{
		"internal/", "server/", "cli/", "scripts/", "deploy/", "docs/",
		"web/src/", "migrations/", "changelog.d/",
	}

	inlineCodeRe = regexp.MustCompile("`([^`\n]+)`")
	lineSuffixRe = regexp.MustCompile(`(:\d+([-,]\d+)*)+$`)

	braceRe   = regexp.MustCompile(`\{([^{}]*)\}`)
	versionRe = regexp.MustCompile(`[vV]?X\.Y\.Z`)

	// symbolSuffixRe drops a trailing `:TestName` / `:funcName` after the file, the form
	// the docs use to point at a symbol; the symbol itself is NOT checked.
	symbolSuffixRe = regexp.MustCompile(`:[A-Za-z_][A-Za-z0-9_]*$`)

	// goSymbolRe is the `pkg/dir.Symbol` / `file.go.Func` form: a capitalised Go identifier
	// chain glued on with dots. Only tried when the path as written does not exist.
	goSymbolRe = regexp.MustCompile(`(\.[A-Z][A-Za-z0-9_]*)+$`)

	// pathRefExcludedName: docs file names that mark an audit/review report.
	pathRefExcludedName = regexp.MustCompile(`(?i)report|findings|census|sweep|measurement|-design\.md$`)
)

// pathRefDocs returns the repo-relative markdown files to scan, sorted.
func pathRefDocs(t testing.TB, root string) []string {
	t.Helper()
	var out []string
	for _, f := range []string{"README.md", "QUICK_START.md", "SELF_HOSTING.md", "RELEASING.md", "migrations/README.md"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			out = append(out, f)
		}
	}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() || !strings.HasSuffix(rel, ".md") || pathRefHistorical(rel) {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	sort.Strings(out)
	return out
}

// pathRefHistorical reports whether a docs/ file is a dated record (see the doc comment).
func pathRefHistorical(rel string) bool {
	for _, p := range []string{
		"docs/adr-", "docs/design", "docs/specs/", "docs/findings/", "docs/triage/",
		"docs/releases/v", "docs/g80-", "docs/cli-split-", "docs/security-review-",
		"docs/cli-migration.md", // header: "FROZEN" snapshot of the deleted internal/cli
	} {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return pathRefExcludedName.MatchString(path.Base(rel))
}

// pathRef is one repo path cited in a document.
type pathRef struct {
	Line int
	Raw  string // the word as written
	Path string // normalised: no ./, :line, #anchor or trailing /...
}

// normalizePathRef turns one word of a code span into a repo path, or "" when the word
// is not a repo path.
func normalizePathRef(word string) string {
	w := strings.Trim(word, "\"'(),;")
	w = strings.TrimPrefix(w, "./")
	hasPrefix := false
	for _, p := range codePathPrefixes {
		if strings.HasPrefix(w, p) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix || strings.Contains(w, "://") {
		return ""
	}
	if i := strings.Index(w, "#"); i >= 0 {
		w = w[:i]
	}
	if i := strings.Index(w, "("); i >= 0 {
		w = w[:i]
	}
	w = strings.TrimSuffix(w, "$")
	w = lineSuffixRe.ReplaceAllString(w, "")
	w = symbolSuffixRe.ReplaceAllString(w, "")
	w = strings.TrimSuffix(w, "/...")
	w = strings.TrimRight(w, ".,:;")
	w = strings.TrimSuffix(w, "/")
	return w
}

// pathRefsIn returns the repo paths cited in the inline code spans of one document.
func pathRefsIn(doc string) []pathRef {
	lines, nums := proseLines(doc)
	var out []pathRef
	for i, line := range lines {
		for _, m := range inlineCodeRe.FindAllStringSubmatch(line, -1) {
			for _, word := range strings.Fields(m[1]) {
				if p := normalizePathRef(word); p != "" {
					out = append(out, pathRef{Line: nums[i], Raw: word, Path: p})
				}
			}
		}
	}
	return out
}

// pathExists resolves a normalised path (possibly with a glob or <placeholder>) under root.
func pathExists(root, p string) bool {
	if m := braceRe.FindStringSubmatchIndex(p); m != nil {
		for _, alt := range strings.Split(p[m[2]:m[3]], ",") {
			if !pathExists(root, p[:m[0]]+alt+p[m[1]:]) {
				return false
			}
		}
		return true
	}
	p = versionRe.ReplaceAllString(p, "<version>")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case strings.Contains(s, "<"):
			return dirOrFileExists(root, strings.Join(segs[:i], "/"))
		case s == "**":
			return dirOrFileExists(root, strings.Join(segs[:i], "/"))
		}
	}
	if strings.ContainsAny(p, "*?[") {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(p)))
		return err == nil && len(m) > 0
	}
	if dirOrFileExists(root, p) {
		return true
	}
	// `internal/keyfiles.Registry`: a Go symbol glued to an existing directory or file.
	trimmed := goSymbolRe.ReplaceAllString(p, "")
	return trimmed != p && dirOrFileExists(root, trimmed)
}

func dirOrFileExists(root, p string) bool {
	if p == "" {
		return true
	}
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)))
	return err == nil
}

func loadPathRefExceptions(t testing.TB) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(codePathExceptions)
	if err != nil {
		t.Fatalf("read %s: %v", codePathExceptions, err)
	}
	out := map[string]bool{}
	for n, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 2 || strings.TrimSpace(f[0]) == "" || strings.TrimSpace(f[1]) == "" {
			t.Fatalf("%s:%d: want path<TAB>reason with a non-empty reason, got %q", codePathExceptions, n+1, line)
		}
		if _, dup := out[f[0]]; dup {
			t.Fatalf("%s:%d: duplicate exception %q", codePathExceptions, n+1, f[0])
		}
		out[f[0]] = false // flips to true when a document needs it
	}
	return out
}

func TestDocsCitedRepoPathsExist(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(t)
	docs := pathRefDocs(t, root)
	if len(docs) < 20 {
		g.Fatalf("only %d documents found to scan: the scan roots moved", len(docs))
	}
	exempt := loadPathRefExceptions(t)

	checked := 0
	for _, rel := range docs {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // repo-relative doc path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, ref := range pathRefsIn(string(b)) {
			checked++
			if pathExists(root, ref.Path) {
				continue
			}
			if _, ok := exempt[ref.Path]; ok {
				exempt[ref.Path] = true
				continue
			}
			g.Errorf("%s:%d cites `%s`, which does not exist: use the current path, delete the sentence, or add a reasoned row to %s", rel, ref.Line, ref.Raw, codePathExceptions)
		}
	}
	for p, used := range exempt {
		if !used {
			g.Errorf("%s: exception %q is not cited by any scanned document, or the path exists now: remove it", codePathExceptions, p)
		}
	}
	g.Logf("%d documents scanned, %d repo path references checked", len(docs), checked)
}

func TestDocsCitedRepoPathsExtraction(t *testing.T) {
	doc := "see `internal/cli/migrate/migrate.go:12` and `server/http/` or `go test ./internal/docsdrift/...`.\n" +
		"```\n`internal/in/fence.go`\n```\n" +
		"`docs/x.md#anchor` `scripts/*.sh` `internal/<pkg>/a.go` `web/src/**/*.tsx` `cmd/other.go` " +
		"`https://example.com/docs/x.md` `--config=deploy/x.yaml` `internal/a.go:3-9:2` `server/x_test.go:TestIt`\n"
	var got []string
	for _, r := range pathRefsIn(doc) {
		got = append(got, r.Path)
	}
	want := []string{
		"internal/cli/migrate/migrate.go", "server/http", "internal/docsdrift",
		"docs/x.md", "scripts/*.sh", "internal/<pkg>/a.go", "web/src/**/*.tsx", "internal/a.go",
		"server/x_test.go",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("extracted\n  %q\nwant\n  %q", got, want)
	}

	root := t.TempDir()
	for _, f := range []string{"internal/a.go", "scripts/x.sh", "web/src/deep/er/c.tsx", "docs/x.md"} {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for p, want := range map[string]bool{
		"internal/a.go": true, "internal": true, "internal/gone.go": false,
		"scripts/*.sh": true, "scripts/*.py": false,
		"internal/<pkg>/zzz.go": true, "nodir/<pkg>/zzz.go": false,
		"web/src/**/*.tsx": true, "web/nosuch/**/*.tsx": false,
		"docs/x.md": true, "docs/y.md": false,
		"internal/{a.go,gone.go}": false, "{internal,docs}/x": false, "scripts/x.{sh,go}": false,
		"docs/{x.md,x.md}": true, "docs/vX.Y.Z.md": true, "nodir/vX.Y.Z.md": false,
		"internal/a.go.Func": true, "internal.Registry": true, "internal/gone.go.Func": false,
	} {
		if got := pathExists(root, p); got != want {
			t.Errorf("pathExists(%q) = %v, want %v", p, got, want)
		}
	}
	if !pathRefHistorical("docs/adr-001-x.md") || !pathRefHistorical("docs/design-b2.md") ||
		!pathRefHistorical("docs/g80-documented-exception-sweep-findings.md") || pathRefHistorical("docs/operator/j5-lost-admin.md") {
		t.Error("historical-document classification is wrong")
	}
}
