package docsdrift

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// DOCS-PATHREF-1 item 3: the operator documents quote `keyorix ...` and
// `keyorix-server admin ...` commands, and a pilot types them literally.
// demo_cli_commands_test.go already resolves such invocations (invocationsOf, the same
// tokenizer and binary-word list) against docs/cli-reference.md for the demo; this test
// points that resolver at the real command trees for the operator documents.
//
// The trees: docs/state-map/entrypoints.tsv is generated from the cobra command
// definitions by cmd/statemapgen and kept fresh by internal/statemap's drift guard, so
// it is the cobra tree itself, not a hand-written list. A `cli` row whose source file
// is under cli/ is a `keyorix` command; one under server/admin/ is a
// `keyorix-server admin` command. A row with no handler is a grouping command: it needs
// a subcommand. (The CLI is a separate Go module and the admin tree is unexported, so
// the test cannot import either.)
//
// What it reads: QUICK_START.md, docs/SELF_HOSTING.md and docs/operator/*.md. Inline code
// spans outside fences, and lines of fenced blocks tagged bash, sh, shell, zsh or
// console (a line starting `#` is a comment and is skipped). Recognised invocation
// forms: `keyorix`, `$KX`, `${KX}`, `$KEYORIX_BIN`, `${KEYORIX_BIN}` (keyorixBinaryWords)
// and `keyorix-server admin`, also behind a directory (`./bin/keyorix`), followed by
// lowercase words, ending at the first flag, placeholder, pipe, `;` or `&&`. The binary
// must be in command position: first on its line or snippet, or right after `|`, `&&`,
// `||`, `;`, `sudo`/`exec`/`time`/`nohup`, or `NAME=value` assignments. That skips
// `pg_dump -U keyorix keyorix`, `for c in keyorix ...` and `helm install keyorix ...`.
//
// It fails when the first word after `keyorix` is not a top-level command, when the
// words after `keyorix-server admin` do not start a known admin command, and when a
// grouping command is followed by a word that is not one of its subcommands. It does
// NOT check flags (the flag set is checked for the demo only), positional arguments
// (a word after a command that runs is an argument), cobra aliases (use the real name
// in the docs), or other `keyorix-server` forms (`keyorix-server --config ...` starts
// the server; only `admin` is resolved). `keyorix-migrate` is another binary.
//
// Exemptions: testdata/doc_cli_exemptions.tsv, `file<TAB>invocation<TAB>reason`; an
// entry that matches nothing is an error.
//
// Report-only on the first day (docs/guard-rollout.d/TestDocsOnlyUseExistingKeyorixCommands.tsv).

const (
	entrypointsTSV       = "docs/state-map/entrypoints.tsv"
	docCLIExemptionsFile = "testdata/doc_cli_exemptions.tsv"
)

// cmdTree maps a command path to whether it is a grouping command (no handler).
type cmdTree map[string]bool

// loadCommandTrees reads the `cli` rows of entrypoints.tsv into the keyorix CLI tree
// (paths like "secret get") and the admin tree (paths like "admin audit verify").
func loadCommandTrees(t testing.TB, root string) (cli, admin cmdTree) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entrypointsTSV))) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	cli, admin = cmdTree{}, cmdTree{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 || f[0] != "cli" || !strings.HasPrefix(f[1], "keyorix") {
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(f[1], "keyorix"))
		group := f[3] == ""
		switch {
		case strings.HasPrefix(f[2], "cli/"):
			if path != "" {
				cli[path] = group
			}
		case strings.HasPrefix(f[2], "server/admin/"):
			admin[strings.TrimSpace("admin "+path)] = group
		}
	}
	// Built into cobra or answered before it; neither is a row in entrypoints.tsv.
	cli["help"], cli["completion"] = false, false
	admin["admin version"] = false
	return cli, admin
}

// docCommandSnippets returns the text snippets of one document that may hold a command:
// inline code spans and shell-fence lines, each with its 1-based line number.
func docCommandSnippets(doc string) (snips []string, lines []int) {
	pl, nums := proseLines(doc)
	for i, l := range pl {
		for _, m := range inlineCodeRe.FindAllStringSubmatch(l, -1) {
			snips = append(snips, m[1])
			lines = append(lines, nums[i])
		}
	}
	for _, f := range fences(doc) {
		switch f.Lang {
		case "bash", "sh", "shell", "zsh", "console":
		default:
			continue
		}
		for i, l := range f.Lines {
			if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "#") {
				snips = append(snips, strings.TrimPrefix(s, "$ "))
				lines = append(lines, f.Line+i)
			}
		}
	}
	return snips, lines
}

var envAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// atCommandPosition reports whether a token that follows prev starts a shell command.
func atCommandPosition(prev string) bool {
	switch prev {
	case "", "|", "&&", "||", ";", "sudo", "exec", "time", "nohup", "then", "do":
		return true
	}
	return envAssignRe.MatchString(prev)
}

// docBinary returns the matcher for a binary name that may be written behind a
// directory (`./bin/keyorix`). A `$VAR` stays as the demo resolver treats it.
func docBinary(name string, extra map[string]bool) func(string) bool {
	return func(tok string) bool {
		if extra[tok] || tok == name {
			return true
		}
		return strings.Contains(tok, "/") && !strings.HasPrefix(tok, "$") && path.Base(tok) == name
	}
}

// unresolvedCommand reports why an invocation does not resolve against tree, or "".
// tree is the CLI tree for `keyorix`, the admin tree for `keyorix-server`.
func unresolvedCommand(inv demoInvocation, tree cmdTree, server bool) string {
	words := inv.Words
	if len(words) == 0 {
		return ""
	}
	if server && words[0] != "admin" {
		return "" // `keyorix-server <flags>` starts the server; not a subcommand tree
	}
	n := len(strings.Fields(inv.Path))
	switch {
	case n == 0:
		return "no command `" + words[0] + "`"
	case n < len(words) && tree[inv.Path]:
		return "`" + inv.Path + "` has no subcommand `" + words[n] + "`"
	}
	return ""
}

func TestDocsOnlyUseExistingKeyorixCommands(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(t)
	cli, admin := loadCommandTrees(t, root)
	if len(cli) < 100 || len(admin) < 15 {
		g.Fatalf("parsed only %d keyorix and %d admin commands from %s: the extraction is broken", len(cli), len(admin), entrypointsTSV)
	}
	exempt := loadDocCLIExemptions(t)

	files := []string{"QUICK_START.md", "docs/SELF_HOSTING.md"}
	ops, err := filepath.Glob(filepath.Join(root, "docs", "operator", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ops {
		rel, _ := filepath.Rel(root, m)
		files = append(files, filepath.ToSlash(rel))
	}
	sort.Strings(files)

	isCLI := docBinary("keyorix", keyorixBinaryWords)
	isServer := docBinary("keyorix-server", nil)
	checked := 0
	for _, rel := range files {
		doc := readDoc(t, rel)
		snips, lines := docCommandSnippets(doc)
		for i, s := range snips {
			for _, side := range []struct {
				bin    func(string) bool
				tree   cmdTree
				server bool
				name   string
			}{{isCLI, cli, false, "keyorix"}, {isServer, admin, true, "keyorix-server"}} {
				known := func(p string) bool { _, ok := side.tree[p]; return ok }
				for _, inv := range invocationsOf(s, side.bin, known) {
					if len(inv.Words) == 0 || !atCommandPosition(inv.Prev) || (side.server && inv.Words[0] != "admin") {
						continue
					}
					checked++
					why := unresolvedCommand(inv, side.tree, side.server)
					if why == "" {
						continue
					}
					key := rel + "\t" + inv.Text
					if _, ok := exempt[key]; ok {
						exempt[key] = true
						continue
					}
					g.Errorf("%s:%d: %s: %s (fix the doc, or add a reasoned row to %s)", rel, lines[i], side.name, why, docCLIExemptionsFile)
				}
			}
		}
	}
	for k, used := range exempt {
		if !used {
			g.Errorf("%s: exemption %q matches no documented command: remove it", docCLIExemptionsFile, k)
		}
	}
	g.Logf("%d documents scanned, %d command invocations checked against %s", len(files), checked, entrypointsTSV)
}

func loadDocCLIExemptions(t testing.TB) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(docCLIExemptionsFile)
	if err != nil {
		t.Fatalf("read %s: %v", docCLIExemptionsFile, err)
	}
	out := map[string]bool{}
	for n, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || strings.TrimSpace(f[2]) == "" {
			t.Fatalf("%s:%d: want file<TAB>invocation<TAB>reason with a non-empty reason, got %q", docCLIExemptionsFile, n+1, line)
		}
		out[f[0]+"\t"+f[1]] = false
	}
	return out
}

func TestDocCommandResolution(t *testing.T) {
	cli := cmdTree{"secret": true, "secret get": false, "login": false, "help": false}
	admin := cmdTree{"admin": true, "admin audit": true, "admin audit verify-audit": false, "admin version": false}
	cliKnown := func(p string) bool { _, ok := cli[p]; return ok }
	adminKnown := func(p string) bool { _, ok := admin[p]; return ok }
	isCLI := docBinary("keyorix", keyorixBinaryWords)
	isServer := docBinary("keyorix-server", nil)

	for _, c := range []struct {
		text   string
		server bool
		want   string // substring of the failure, "" for resolves
	}{
		{"keyorix login", false, ""},
		{"keyorix secret get my-secret --project 3", false, ""},
		{"keyorix login again", false, ""}, // `login` runs: `again` is an argument
		{"keyorix secret nosuch", false, "no subcommand `nosuch`"},
		{"keyorix nosuch thing", false, "no command `nosuch`"},
		{"keyorix <command> --help", false, ""},
		{"keyorix --version", false, ""},
		{"keyorix-server admin audit verify-audit --json", true, ""},
		{"keyorix-server admin audit gone", true, "no subcommand `gone`"},
		{"keyorix-server admin nosuch", true, "no subcommand `nosuch`"},
		{"keyorix-server --config x.yaml", true, ""},
		{"keyorix-server admin", true, ""},
		{"./bin/keyorix secret nosuch", false, "no subcommand `nosuch`"},
		{"/usr/local/bin/keyorix-server admin audit gone", true, "no subcommand `gone`"},
		{"FOO=1 keyorix nosuch", false, "no command `nosuch`"},
		{"docker compose exec postgres pg_dump -U keyorix keyorix | gzip", false, "SKIP"},
		{"for c in keyorix keyorix-k8s-sync; do", false, "SKIP"},
		{"helm upgrade --install keyorix deploy/helm/keyorix", false, "SKIP"},
		{"echo hi | keyorix nosuch", false, "no command `nosuch`"},
	} {
		tree, bin, known := cli, isCLI, cliKnown
		if c.server {
			tree, bin, known = admin, isServer, adminKnown
		}
		var got []string
		for _, inv := range invocationsOf(c.text, bin, known) {
			if !atCommandPosition(inv.Prev) {
				continue
			}
			if why := unresolvedCommand(inv, tree, c.server); why != "" {
				got = append(got, why)
			}
		}
		switch {
		case c.want == "" || c.want == "SKIP":
			if len(got) != 0 {
				t.Errorf("%q: must resolve or be skipped, got %q", c.text, got)
			}
		case len(got) != 1 || !strings.Contains(got[0], c.want):
			t.Errorf("%q: got %q, want exactly one failure containing %q", c.text, got, c.want)
		}
	}
}
