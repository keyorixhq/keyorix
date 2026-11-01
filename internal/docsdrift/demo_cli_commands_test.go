package docsdrift

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// VAULT-MIGRATION-DEMO-1 (#3638): the "migrate off Vault" demo told pilots to run
// `keyorix secret import --source vault`, a command the thin CLI dropped when live
// sources moved to keyorix-migrate (ADR-108). Nothing noticed, because no check read
// the demo.
//
// What it reads: every `*.sh` and `*.md` under demo/ (comments and prose included, a
// backslash continuation is joined to its first line). A `keyorix ...` invocation is
// the word `keyorix` or a shell variable that holds the binary ($KX, $KEYORIX_BIN),
// followed by subcommand words, followed by flags; it ends at a pipe, `;` or `&&`.
// It fails on
//
//  1. `keyorix secret import --source`, by name: the exact regression above, kept
//     even if someone later documents a --source flag on the CLI, and
//  2. any `--flag` on a line whose command path matches a `## `keyorix <path>``
//     section of docs/cli-reference.md when that section (or the Global flags
//     table) does not list the flag.
//
// What it does NOT read: demo files of other types (app.js, YAML), a `keyorix` line
// whose words do not resolve to a documented command (prose such as "the keyorix CLI
// no longer ..." is skipped, not failed), flags on `keyorix-migrate` lines (a different
// binary, covered by docs/migrate-from-vault.md), and flag values. The command path is
// the longest documented prefix, so a subcommand that no longer exists is only caught
// when its parent still exists and the flag is not the parent's.
//
// Exemptions: testdata/demo_cli_exemptions.tsv, one `file<TAB>command<TAB>flag<TAB>reason`
// row each. An entry that matches nothing is itself an error, so the file cannot rot.

const (
	cliReferenceDoc    = "docs/cli-reference.md"
	demoCLIExemptions  = "testdata/demo_cli_exemptions.tsv"
	cliGlobalFlagsHead = "global flags"
)

var (
	cliSectionRe = regexp.MustCompile("^## `keyorix([a-z0-9 -]*)`\\s*$")
	cliFlagCell  = regexp.MustCompile("`(--[a-z][a-z0-9-]*)`")
	flagTokenRe  = regexp.MustCompile(`^(--[a-z][a-z0-9-]*)`)
	wordTokenRe  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	importSrcRe  = regexp.MustCompile(`\bsecret\s+import\b[^|;&]*\s--source\b`)

	// builtinFlags exist on every cobra command without appearing in the reference tables.
	builtinFlags = map[string]bool{"--help": true, "--version": true}

	// keyorixBinaryWords are the tokens (after stripping quotes, backticks and `$(`) that
	// stand for the keyorix binary in the demo scripts. The list is the recognised
	// invocation forms; a script that stores the binary under another name is not seen.
	keyorixBinaryWords = map[string]bool{
		"keyorix": true, "$KX": true, "${KX}": true, "$KEYORIX_BIN": true, "${KEYORIX_BIN}": true,
	}
)

// cliFlagTable maps a command path ("secret import"; "" for the root) to its flags.
type cliFlagTable struct {
	byCmd  map[string]map[string]bool
	global map[string]bool
}

func parseCLIReference(md string) cliFlagTable {
	tbl := cliFlagTable{byCmd: map[string]map[string]bool{}, global: map[string]bool{}}
	var cur map[string]bool
	for line := range strings.SplitSeq(md, "\n") {
		if m := cliSectionRe.FindStringSubmatch(line); m != nil {
			path := strings.TrimSpace(m[1])
			cur = map[string]bool{}
			tbl.byCmd[path] = cur
			continue
		}
		if strings.HasPrefix(line, "## ") {
			cur = nil
			if strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "## ")), cliGlobalFlagsHead) {
				cur = tbl.global
			}
			continue
		}
		if cur == nil || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.SplitN(line, "|", 3)
		if len(cells) < 3 {
			continue
		}
		for _, m := range cliFlagCell.FindAllStringSubmatch(cells[1], -1) {
			cur[m[1]] = true
		}
	}
	return tbl
}

// demoInvocation is one `keyorix <path> --flags` occurrence.
type demoInvocation struct {
	Line  int
	Path  string // longest documented command path; "" when none resolved
	Flags []string
	Text  string
}

func cleanToken(s string) string {
	s = strings.TrimLeft(s, "`\"'($")
	s = strings.TrimRight(s, "`\"')")
	return s
}

// binaryToken is cleanToken that keeps a leading `$`, so $KX and ${KX} survive.
func binaryToken(s string) string {
	s = strings.TrimLeft(s, "`\"'(")
	s = strings.TrimRight(s, "`\"')")
	return s
}

// invocationsIn returns the keyorix invocations of one file's text. known resolves a
// candidate path to documented-or-not.
func invocationsIn(text string, known func(path string) bool) []demoInvocation {
	text = strings.ReplaceAll(text, "\\\n", " ")
	var out []demoInvocation
	for i, line := range strings.Split(text, "\n") {
		toks := strings.Fields(line)
		for j := range toks {
			if !keyorixBinaryWords[binaryToken(toks[j])] {
				continue
			}
			var words []string
			k := j + 1
			for ; k < len(toks) && wordTokenRe.MatchString(cleanToken(toks[k])) && !strings.ContainsAny(toks[k], "|;&"); k++ {
				words = append(words, cleanToken(toks[k]))
			}
			path := ""
			for n := len(words); n >= 1; n-- {
				if p := strings.Join(words[:n], " "); known(p) {
					path = p
					break
				}
			}
			var flags []string
			for ; k < len(toks); k++ {
				t := toks[k]
				if t == "|" || t == ";" || t == "&&" || t == "||" || keyorixBinaryWords[binaryToken(t)] {
					break
				}
				if m := flagTokenRe.FindStringSubmatch(cleanToken(t)); m != nil {
					flags = append(flags, m[1])
				}
			}
			out = append(out, demoInvocation{Line: i + 1, Path: path, Flags: flags, Text: strings.TrimSpace(line)})
		}
	}
	return out
}

type demoExemption struct{ file, cmd, flag string }

func loadDemoExemptions(t testing.TB) map[demoExemption]bool {
	t.Helper()
	b, err := os.ReadFile(demoCLIExemptions)
	if err != nil {
		t.Fatalf("read %s: %v", demoCLIExemptions, err)
	}
	out := map[demoExemption]bool{}
	for n, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 || strings.TrimSpace(f[3]) == "" {
			t.Fatalf("%s:%d: want file<TAB>command<TAB>flag<TAB>reason with a non-empty reason, got %q", demoCLIExemptions, n+1, line)
		}
		e := demoExemption{f[0], f[1], f[2]}
		if out[e] {
			t.Fatalf("%s:%d: duplicate exemption %v", demoCLIExemptions, n+1, e)
		}
		out[e] = false // value flips to true when an invocation uses it
	}
	return out
}

func TestDemoScriptsOnlyUseDocumentedKeyorixCommands(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(t)
	ref, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(cliReferenceDoc))) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	tbl := parseCLIReference(string(ref))
	if len(tbl.byCmd) < 20 || len(tbl.global) == 0 {
		g.Fatalf("parsed only %d commands and %d global flags from %s: the extraction is broken", len(tbl.byCmd), len(tbl.global), cliReferenceDoc)
	}
	known := func(p string) bool { _, ok := tbl.byCmd[p]; return ok }
	exempt := loadDemoExemptions(t)

	var files []string
	err = filepath.WalkDir(filepath.Join(root, "demo"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".sh") || strings.HasSuffix(p, ".md")) {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk demo: %v", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		g.Fatalf("no *.sh or *.md under demo/: the scan root moved")
	}

	checked := 0
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // repo-relative demo path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, inv := range invocationsIn(string(b), known) {
			if importSrcRe.MatchString(inv.Text) {
				g.Errorf("%s:%d runs `keyorix secret import --source`, which the CLI no longer has: use keyorix-migrate (docs/migrate-from-vault.md): %s", rel, inv.Line, inv.Text)
				continue
			}
			if inv.Path == "" {
				continue
			}
			for _, f := range inv.Flags {
				checked++
				if builtinFlags[f] || tbl.global[f] || tbl.byCmd[inv.Path][f] {
					continue
				}
				e := demoExemption{rel, inv.Path, f}
				if _, ok := exempt[e]; ok {
					exempt[e] = true
					continue
				}
				g.Errorf("%s:%d: `keyorix %s` has no flag %s in %s (fix the demo, or add a reasoned row to %s): %s", rel, inv.Line, inv.Path, f, cliReferenceDoc, demoCLIExemptions, inv.Text)
			}
		}
	}
	for e, used := range exempt {
		if !used {
			g.Errorf("%s: exemption %v matches no demo line: remove it", demoCLIExemptions, e)
		}
	}
	g.Logf("%d demo files scanned, %d keyorix flags checked against %s", len(files), checked, cliReferenceDoc)
}

func TestDemoCLIExtraction(t *testing.T) {
	md := "# t\n\n## Global flags\n\n| Flag |\n|---|\n| `--ca-file` |\n\n" +
		"## `keyorix secret import`\n\n| Flag | Type |\n|---|---|\n| `--file` | `string` |\n| `--project` | `int` |\n\n" +
		"## `keyorix secret`\n\n| Flag |\n|---|\n| `--output` |\n"
	tbl := parseCLIReference(md)
	if !tbl.global["--ca-file"] || !tbl.byCmd["secret import"]["--file"] || tbl.byCmd["secret import"]["--output"] {
		t.Fatalf("parse: %+v", tbl)
	}
	known := func(p string) bool { _, ok := tbl.byCmd[p]; return ok }

	text := "keyorix secret import --file a.env \\\n  --bogus 1 | jq --raw-output .\n" +
		"\"$KX\" secret import --source vault\n" +
		"the keyorix CLI no longer imports\n" +
		"keyorix-migrate vault --apply\n" +
		"echo `keyorix secret --output json`\n"
	got := invocationsIn(text, known)
	if len(got) != 4 {
		t.Fatalf("want 4 invocations, got %d: %+v", len(got), got)
	}
	if got[0].Path != "secret import" || strings.Join(got[0].Flags, ",") != "--file,--bogus" {
		t.Errorf("continuation + pipe stop: %+v", got[0])
	}
	if !importSrcRe.MatchString(got[1].Text) || got[1].Path != "secret import" {
		t.Errorf("$KX form not seen: %+v", got[1])
	}
	if got[2].Path != "" {
		t.Errorf("prose must not resolve to a command: %+v", got[2])
	}
	if got[3].Path != "secret" || strings.Join(got[3].Flags, ",") != "--output" {
		t.Errorf("backtick form: %+v", got[3])
	}
	if importSrcRe.MatchString("keyorix secret import --file x") {
		t.Error("a plain secret import must not trip the --source rule")
	}
}
