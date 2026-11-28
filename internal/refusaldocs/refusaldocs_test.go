// Package refusaldocs keeps docs/operator/startup-refusals.md honest.
//
// The page tells an operator what each start-up refusal looks like and how to
// fix it. Every entry carries a "Match" text: the stable part of the message.
// TestDocumentedRefusalsExistInCode fails when a Match text is no longer a
// string in the Go sources (the message was reworded or removed, so the page
// would send an operator searching for text that no build prints).
//
// Direction: docs -> code only is fatal. This direction cannot conflict with
// another PR: reworking a message is the author's job and the failure names the
// page entry to update.
//
// The other direction, code -> docs, is logged and NOT fatal
// (TestUndocumentedRefusalsAreListed prints the list; run with -v). Parallel
// work adds refusals to server/main.go and internal/config all the time, and a
// test that failed for each new one would block unrelated PRs on a docs edit
// they may not own. The list is the to-do for the page's next update.
//
// What the test cannot see (stated here so a green run is not over-read):
//   - Messages built from variables or helpers at run time. Literals are
//     found, and "a" + "b" concatenations of literals are folded (that is how
//     multi-line messages and the single_writer constants are written), but a
//     message that includes a named constant, a Sprintf'd fragment or text read
//     from a file is only matched on its literal pieces.
//   - Whether the page's "Real output" blocks are what the binary prints today.
//     Only the Match text is checked; the pasted output was produced by hand.
//   - Whether the cause or fix text is right.
//   - Refusals that never pass through fmt.Errorf / errors.New / log.Fatalf
//     with a literal first argument (for example a message passed through an
//     i18n lookup). The code -> docs list is built from those three call
//     forms in the boot-path packages only; see candidateDirs.
//   - Go sources outside server/ and internal/ (the cli module).
package refusaldocs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const docPath = "docs/operator/startup-refusals.md"

// sourceRoots are the directories whose non-test Go files make up the corpus
// a Match text is looked up in.
var sourceRoots = []string{"server", "internal"}

// candidateDirs are the boot-path locations scanned for the code -> docs list.
// A candidate is a literal passed to fmt.Errorf, errors.New or log.Fatal(f)
// that reads as a refusal (contains "refus"), plus every log.Fatalf message in
// the server's package main (server/*.go: main.go and the per-domain boot files
// it calls), which are refusals by construction. An entry with a "*" is a glob
// over one directory, not a recursive walk.
var candidateDirs = []string{
	"server/*.go",
	"server/admin",
	"internal/config",
	"internal/storage/factory.go",
	"internal/storage/factory_schema_epoch.go",
	"internal/storage/factory_local.go",
	"internal/storage/factory_postgres.go",
	"internal/storage/postgres_open.go",
	"internal/serverguard",
	"internal/solewriter",
	"internal/keyfiles",
	"internal/startup",
	"internal/secretenv",
	"internal/crypto/passphrase.go",
	"internal/encryption/exclusive_lock.go",
	"internal/encryptionops",
}

// minMatchLen keeps a Match from being a word that appears everywhere.
const minMatchLen = 15

var (
	matchLine = regexp.MustCompile(`^\*\*Match:\*\*(.*)$`)
	codeSpan  = regexp.MustCompile("`([^`]+)`")

	formatVerb = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)
)

// docMatches returns the Match texts of the page: every `code` span in a
// "**Match:**" paragraph (the line that starts with it and any lines that
// follow it up to the next blank line), and the first-column code span of each
// row of a table whose header's first cell is "Match".
func docMatches(markdown string) []string {
	var out []string
	inMatchTable := false
	inMatchPara := false
	for line := range strings.SplitSeq(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			inMatchPara = false
		}
		if m := matchLine.FindStringSubmatch(trimmed); m != nil {
			inMatchPara = true
			for _, s := range codeSpan.FindAllStringSubmatch(m[1], -1) {
				out = append(out, s[1])
			}
			continue
		}
		if inMatchPara {
			for _, s := range codeSpan.FindAllStringSubmatch(trimmed, -1) {
				out = append(out, s[1])
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "|") {
			inMatchTable = false
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		first := strings.TrimSpace(cells[0])
		switch {
		case first == "Match":
			inMatchTable = true
		case inMatchTable && !strings.HasPrefix(first, "---"):
			for _, s := range codeSpan.FindAllStringSubmatch(first, -1) {
				out = append(out, s[1])
			}
		}
	}
	return out
}

// foldString returns the value of e when it is a string literal or a +
// concatenation of them (parenthesised or not).
func foldString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return foldString(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok := foldString(x.X)
		if !ok {
			return "", false
		}
		r, ok := foldString(x.Y)
		if !ok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// goFiles lists non-test .go files under root/rel (rel may be a file).
func goFiles(root, rel string) ([]string, error) {
	var files []string
	if strings.Contains(rel, "*") {
		matches, err := filepath.Glob(filepath.Join(root, rel))
		if err != nil {
			return nil, err
		}
		for _, p := range matches {
			if !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
		}
		return files, nil
	}
	start := filepath.Join(root, rel)
	info, err := os.Stat(start)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return []string{start}, nil
	}
	err = filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", ".scratch", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// literals returns every string a file spells out: each literal, and each
// folded concatenation of literals.
func literals(path string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BasicLit, *ast.BinaryExpr:
			if s, ok := foldString(e.(ast.Expr)); ok {
				out = append(out, s)
			}
		}
		return true
	})
	return out, nil
}

// candidates returns the refusal-looking messages of one file, keyed by text.
func candidates(path string, isMain bool) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
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
		fatal := name == "log.Fatalf" || name == "log.Fatal"
		if name != "fmt.Errorf" && name != "errors.New" && !fatal {
			return true
		}
		s, ok := foldString(call.Args[0])
		if !ok {
			return true
		}
		// "Configuration is invalid: %v" style wrappers only name the stage that
		// refused; the page describes the stages once, in "How to read an entry".
		if len(strings.TrimSpace(formatVerb.ReplaceAllString(s, ""))) < 25 {
			return true
		}
		if strings.Contains(strings.ToLower(s), "refus") || (fatal && isMain) {
			out = append(out, s)
		}
		return true
	})
	return out, nil
}

// result is what one check of a tree produced.
type result struct {
	matches      []string // Match texts found in the page
	missing      []string // Match texts with no string in the sources
	short        []string // Match texts too short to mean anything
	undocumented []string // refusal-looking messages no Match text is part of
}

// check compares the page under root with the Go sources under root.
func check(root string) (result, error) {
	var r result
	doc, err := os.ReadFile(filepath.Join(root, docPath))
	if err != nil {
		return r, err
	}
	r.matches = docMatches(string(doc))

	var corpus []string
	for _, rel := range sourceRoots {
		files, err := goFiles(root, rel)
		if err != nil {
			return r, err
		}
		for _, f := range files {
			lits, err := literals(f)
			if err != nil {
				return r, err
			}
			corpus = append(corpus, lits...)
		}
	}
	for _, m := range r.matches {
		if len(m) < minMatchLen {
			r.short = append(r.short, m)
			continue
		}
		found := false
		for _, s := range corpus {
			if strings.Contains(s, m) {
				found = true
				break
			}
		}
		if !found {
			r.missing = append(r.missing, m)
		}
	}

	seen := map[string]bool{}
	for _, rel := range candidateDirs {
		files, err := goFiles(root, rel)
		if err != nil {
			return r, err
		}
		for _, f := range files {
			cands, err := candidates(f, filepath.Dir(f) == filepath.Join(root, "server"))
			if err != nil {
				return r, err
			}
			for _, c := range cands {
				if seen[c] {
					continue
				}
				seen[c] = true
				documented := false
				for _, m := range r.matches {
					if strings.Contains(c, m) {
						documented = true
						break
					}
				}
				if !documented {
					r.undocumented = append(r.undocumented, c)
				}
			}
		}
	}
	sort.Strings(r.undocumented)
	return r, nil
}

// repoRoot is the module root, or KEYORIX_REFUSALDOCS_ROOT when set (a scratch
// copy of the tree, used to show the test red).
func repoRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("KEYORIX_REFUSALDOCS_ROOT"); v != "" {
		return v
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// TestDocumentedRefusalsExistInCode is the fatal direction: docs -> code.
func TestDocumentedRefusalsExistInCode(t *testing.T) {
	r, err := check(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.matches) == 0 {
		t.Fatalf("%s has no Match texts: the page lost its machine-checked entries", docPath)
	}
	for _, m := range r.short {
		t.Errorf("%s: Match text %q is shorter than %d characters; a short text matches unrelated code, name the stable part of the message", docPath, m, minMatchLen)
	}
	for _, m := range r.missing {
		t.Errorf("%s: Match text %q is not a string in any Go file under %s: the message was reworded or removed; update the page entry (message, cause, fix) to the new text",
			docPath, m, strings.Join(sourceRoots, ", "))
	}
	t.Logf("%d Match texts checked against the Go sources", len(r.matches))
}

// TestUndocumentedRefusalsAreListed is the code -> docs direction: it logs,
// never fails. See the package comment for why.
func TestUndocumentedRefusalsAreListed(t *testing.T) {
	r, err := check(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d refusal-looking messages in the boot-path packages have no Match text on %s (not a failure; update the page when convenient):",
		len(r.undocumented), docPath)
	for _, u := range r.undocumented {
		if len(u) > 160 {
			u = u[:160] + "..."
		}
		t.Logf("  undocumented: %s", strings.ReplaceAll(u, "\n", " "))
	}
}

// TestCheckerSeesRenamedMessage shows the checker red and green on a tiny
// synthetic tree, so the guard has been watched to fail without touching the
// real sources: the page's Match text is present, then the message is renamed.
func TestCheckerSeesRenamedMessage(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	doc := "**Match:** `the widget is not configured`\n\n" +
		"| Match | meaning |\n|---|---|\n| `split across a concatenation` | x |\n"
	write(docPath, doc)
	good := "package x\nimport \"fmt\"\nfunc f() error {\n" +
		"\treturn fmt.Errorf(\"the widget is not configured: %w\", nil)\n}\n" +
		"var g = \"split across \" +\n\t\"a concatenation\"\n"
	write("internal/x/x.go", good)

	r, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.matches) != 2 || len(r.missing) != 0 || len(r.short) != 0 {
		t.Fatalf("green case: matches=%v missing=%v short=%v", r.matches, r.missing, r.short)
	}

	write("internal/x/x.go", strings.Replace(good, "the widget is not configured", "the gadget is not configured", 1))
	r, err = check(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.missing) != 1 || r.missing[0] != "the widget is not configured" {
		t.Fatalf("red case: renamed message not reported: missing=%v", r.missing)
	}
}

func TestDocMatchesParsing(t *testing.T) {
	md := "**Match:** `first text here`, `second text here`,\n`continued on next line`\n\n" +
		"prose with `not a match`\n\n" +
		"| Match | What |\n|---|---|\n| `row one match` | `ignored span` |\n\n" +
		"| Other | What |\n|---|---|\n| `not in a match table` | y |\n"
	got := strings.Join(docMatches(md), "|")
	want := "first text here|second text here|continued on next line|row one match"
	if got != want {
		t.Fatalf("docMatches = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Exit statuses (BOOT-REFUSAL-TRUTH-NOV-1). These tests live in this file, not
// in a file of their own, because scripts/ci/guard-inputs.d maps
// docs/operator/startup-refusals.md to refusaldocs_test.go: a docs-only change
// to the page must select them too (CI-GUARD-TRIGGERS-1).
//
// Fatal checks, each small on purpose (the general code -> docs direction
// stays log-only, see the package comment):
//
//   - TestExitStatusTableUsesTheServersStatuses: the statuses in the table are
//     exactly the two server/boot_exit.go defines plus 1. A renumbered status
//     (or a fourth one added to the code) makes the page lie to an operator who
//     writes RestartPreventExitStatus= from it.
//   - TestOperatorFixRefusalsAreDocumented: the refusals that were exit 1 and
//     were moved to 78 (EXIT78-1, BOOT-REFUSAL-TRUTH-NOV-1) keep a Match entry on
//     the page. The list is hand-kept: it names the refusals a systemd unit
//     stops on that are not plain configuration errors, and a new one is added
//     here when it is marked. What it does not see: an operatorFix call whose
//     message is not in this list.
//   - TestReplicationRoleEntryGivesAdminStatus: the session_replication_role
//     entry does not say admin exits 1 (it exits 78 since this change).
//   - TestAdminExitStatusParagraphNamesEveryCode: every non-1 status that
//     server/admin passes to newExitCodeError (a literal, or a package-level
//     constant with a literal value) is named in the admin paragraph of the
//     page. What it does not see: a status computed at run time (verify-audit's
//     result.ExitCode(), whose values the verify-audit entry documents) and an
//     exit status set any other way than newExitCodeError.

var (
	statusConst = regexp.MustCompile(`(?m)^\s*(exitOperatorFix|exitDependencyDown)\s*=\s*(\d+)\s*$`)
	statusRow   = regexp.MustCompile(`^\|\s*(\d+)\s*\|`)
)

// tableStatuses returns the distinct statuses in the first column of the
// "Exit statuses" table, in ascending order.
func tableStatuses(markdown string) []int {
	set := map[int]bool{}
	inSection := false
	for line := range strings.SplitSeq(markdown, "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			inSection = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Exit statuses"
		case inSection:
			if m := statusRow.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				n, _ := strconv.Atoi(m[1])
				set[n] = true
			}
		}
	}
	var out []int
	for n := range set {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func TestExitStatusTableUsesTheServersStatuses(t *testing.T) {
	root := repoRoot(t)
	code, err := os.ReadFile(filepath.Join(root, "server", "boot_exit.go")) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{1: true} // "everything else", documented in boot_exit.go's header
	consts := statusConst.FindAllStringSubmatch(string(code), -1)
	if len(consts) != 2 {
		t.Fatalf("server/boot_exit.go: found %d exit status constants, want exitOperatorFix and exitDependencyDown: the checker needs updating", len(consts))
	}
	for _, c := range consts {
		n, _ := strconv.Atoi(c[2])
		want[n] = true
	}
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docPath))) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	got := tableStatuses(string(doc))
	if len(got) == 0 {
		t.Fatalf("%s: no rows found under \"## Exit statuses\"", docPath)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("%s: the Exit statuses table lists status %d, which server/boot_exit.go does not define", docPath, n)
		}
		delete(want, n)
	}
	for n := range want {
		t.Errorf("%s: the Exit statuses table has no row for status %d, which server/boot_exit.go defines", docPath, n)
	}
}

func TestOperatorFixRefusalsAreDocumented(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docPath))) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	matches := docMatches(string(doc))
	for _, need := range []string{
		"KEYORIX_BOOTSTRAP_TOKEN too short",                    // server/bootstrap_token.go, exit 78
		"PostgreSQL session_replication_role is",               // storage.NonOriginReplicationRoleError, exit 78 (server and admin)
		"existing row group(s) normalize to the same identity", // storage.FoldCollisionError (78 for projects only), text shared by all tables
	} {
		found := false
		for _, m := range matches {
			// One direction only: a Match shortened to a fragment of the
			// needle (`PostgreSQL`) would otherwise still pass.
			if strings.Contains(m, need) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s has no Match entry for %q, a refusal the server exits 78 for", docPath, need)
		}
	}
}

func TestTableStatusesParsing(t *testing.T) {
	md := "| 78 | before the section |\n\n## Exit statuses\n\n| Exit | What |\n|---|---|\n| 78 | a |\n| 75 | b |\n| 78 | c |\n| 1 | d |\n\n## Next\n\n| 2 | after |\n"
	got := tableStatuses(md)
	if len(got) != 3 || got[0] != 1 || got[1] != 75 || got[2] != 78 {
		t.Fatalf("tableStatuses = %v, want [1 75 78]", got)
	}
}

// sectionText returns the text under the "### "+title heading up to the next
// heading of level 3 or higher, or "" when there is no such heading.
func sectionText(markdown, title string) string {
	var b strings.Builder
	in := false
	for line := range strings.SplitSeq(markdown, "\n") {
		if strings.HasPrefix(line, "### ") || strings.HasPrefix(line, "## ") {
			if in {
				break
			}
			in = strings.TrimSpace(strings.TrimPrefix(line, "### ")) == title
			continue
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

var exitsOne = regexp.MustCompile(`(?i)\bexit(s| code| status)?:?\*{0,2} 1\b`)

func TestReplicationRoleEntryGivesAdminStatus(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docPath))) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	const title = "`session_replication_role` is not `origin`"
	sec := sectionText(string(doc), title)
	if sec == "" {
		t.Fatalf("%s: no section %q", docPath, title)
	}
	// "earlier builds exited 1" is history and allowed; a present-tense
	// "exits 1" / "exit code 1" is the stale claim.
	if m := exitsOne.FindString(sec); m != "" {
		t.Errorf("%s: section %q says %q, but admin commands exit 78 for this refusal (server/admin adminExitCode)", docPath, title, m)
	}
	if !strings.Contains(sec, "exits 78") {
		t.Errorf("%s: section %q does not say that admin exits 78 for this refusal", docPath, title)
	}
}

// adminExitCodes returns the distinct statuses passed to newExitCodeError in
// the non-test Go files of server/admin, as an int literal or as a
// package-level constant with an int literal value. unresolved counts the calls
// whose status is neither (computed at run time).
func adminExitCodes(dir string) (codes []int, unresolved int, err error) {
	fset := token.NewFileSet()
	var files []*ast.File
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, 0, perr
		}
		files = append(files, f)
	}
	consts := map[string]int{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.INT {
							v, _ := strconv.Atoi(lit.Value)
							consts[n.Name] = v
						}
					}
				}
			}
		}
	}
	set := map[int]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "newExitCodeError" {
				return true
			}
			switch a := call.Args[0].(type) {
			case *ast.BasicLit:
				if a.Kind == token.INT {
					v, _ := strconv.Atoi(a.Value)
					set[v] = true
					return true
				}
			case *ast.Ident:
				if v, ok := consts[a.Name]; ok {
					set[v] = true
					return true
				}
			}
			unresolved++
			return true
		})
	}
	for v := range set {
		codes = append(codes, v)
	}
	sort.Ints(codes)
	return codes, unresolved, nil
}

// adminParagraph returns the paragraph of the page that starts with the admin
// exit-status sentence, or "".
func adminParagraph(markdown string) string {
	const start = "`keyorix-server admin <command>` exits 1 for a failure"
	i := strings.Index(markdown, start)
	if i < 0 {
		return ""
	}
	p := markdown[i:]
	if j := strings.Index(p, "\n\n"); j >= 0 {
		p = p[:j]
	}
	return p
}

func TestAdminExitStatusParagraphNamesEveryCode(t *testing.T) {
	root := repoRoot(t)
	codes, unresolved, err := adminExitCodes(filepath.Join(root, "server", "admin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) == 0 {
		t.Fatal("server/admin: no newExitCodeError status found: the checker needs updating")
	}
	t.Logf("server/admin newExitCodeError statuses: %v (%d computed at run time, not checked)", codes, unresolved)
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docPath))) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	para := adminParagraph(string(doc))
	if para == "" {
		t.Fatalf("%s: the admin exit-status paragraph (\"`keyorix-server admin <command>` exits 1 for a failure ...\") is missing", docPath)
	}
	// 78 is set by adminExitCode for the replication-role refusal, not by
	// newExitCodeError; it is checked the same way.
	codes = append(codes, 78)
	for _, c := range codes {
		if c == 1 {
			continue
		}
		if !regexp.MustCompile(`\bexits ` + strconv.Itoa(c) + `\b|\(` + strconv.Itoa(c) + ` `).MatchString(para) {
			t.Errorf("%s: the admin exit-status paragraph does not name status %d, which server/admin can exit with", docPath, c)
		}
	}
}

func TestAdminExitCodesParsing(t *testing.T) {
	dir := t.TempDir()
	src := "package admin\n\nconst aExitCode = 4\n\nfunc f(r interface{ ExitCode() int }) {\n" +
		"\t_ = newExitCodeError(aExitCode, nil)\n\t_ = newExitCodeError(2, nil)\n\t_ = newExitCodeError(r.ExitCode(), nil)\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a_test.go"), []byte("package admin\n\nfunc g() { _ = newExitCodeError(9, nil) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := adminExitCodes(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 2 || codes[0] != 2 || codes[1] != 4 || unresolved != 1 {
		t.Fatalf("adminExitCodes = %v, %d unresolved; want [2 4], 1", codes, unresolved)
	}
	para := adminParagraph("x\n\n`keyorix-server admin <command>` exits 1 for a failure unless; backup\nexits 4 when.\n\nexits 2 is in the next paragraph\n")
	if !strings.Contains(para, "exits 4") || strings.Contains(para, "exits 2") {
		t.Fatalf("adminParagraph = %q", para)
	}
	sec := sectionText("### A\nexits 1\n### B\nkeep\n## C\nno\n", "B")
	if sec != "keep\n" {
		t.Fatalf("sectionText = %q", sec)
	}
	if !exitsOne.MatchString("and keeps the `admin` exit code 1.") || exitsOne.MatchString("earlier builds exited 1") {
		t.Fatal("exitsOne: wrong match")
	}
}
