// quickstart_commands_test.go — QUICK_START.md is the first file a new user or
// an evaluating architect opens, and every command in it is a promise. The
// version this replaced had four commands that could not work: `share create
// --recipient "colleague@company.com"` (the flag is --recipient-id, and it is a
// uint), a docker-compose file that does not exist, binary paths that predate
// BUILD_DIR=./bin, and a config block that omitted KEYORIX_MASTER_PASSWORD so
// the documented setup could not start. Nothing detected any of it, because a
// document cannot fail.
//
// This test makes it fail. It walks the real cobra tree -- not a parse of the
// source -- and asserts that every `./bin/keyorix ...` invocation in
// QUICK_START.md resolves to a real command with real flags. Rename a flag and
// this goes red in the same commit, which is the only moment anyone has the
// context to fix the prose.
//
// Scope, stated so a green run is not read as more than it is: this verifies
// that commands and flags EXIST. It does not run them, does not check flag
// values or argument counts, and says nothing about whether the surrounding
// prose is true.
//
// See CLAUDE.md, "Core principle: prefer the machine-checked over the asserted."
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cobraBuiltinFlags are added by cobra at Execute time, not at registration, so
// they are absent from the tree a test inspects. They are valid in the doc.
var cobraBuiltinFlags = map[string]bool{"help": true, "version": true}

// tokenize splits a shell-ish command line, honouring single and double quotes
// so that a value containing spaces does not become two tokens.
func tokenize(line string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// quickstartInvocations extracts every ./bin/keyorix invocation from the doc,
// joining backslash continuations first. Lines invoking keyorix-server, make,
// docker or an env-var export are not CLI commands and are skipped.
func quickstartInvocations(t *testing.T) [][]string {
	t.Helper()
	path := filepath.Join("..", "..", "QUICK_START.md")
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	// Join `\`-continued lines into one logical line.
	joined := strings.ReplaceAll(string(b), "\\\n", " ")

	var out [][]string
	inFence := false
	for _, line := range strings.Split(joined, "\n") {
		line = strings.TrimSpace(line)
		// Only fenced code blocks are runnable examples. Prose mentions the
		// binary too ("Produces ./bin/keyorix (CLI)"), and an inline-code
		// mention drags markdown backticks into the tokens -- both produced
		// false failures before this guard restricted itself to fences.
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i]) // strip trailing shell comments
		}
		const bin = "./bin/keyorix"
		i := strings.Index(line, bin)
		if i < 0 || strings.HasPrefix(line[i:], bin+"-server") {
			continue
		}
		toks := tokenize(line[i+len(bin):])
		if len(toks) == 0 {
			continue
		}
		out = append(out, toks)
	}
	return out
}

// TestQuickStartCommandsExist is the guard described in this file's header.
func TestQuickStartCommandsExist(t *testing.T) {
	t.Parallel()

	invocations := quickstartInvocations(t)
	// A doc that stopped containing commands, or an extractor that stopped
	// matching them, would make this test silently vacuous. Both are failures.
	if len(invocations) < 8 {
		t.Fatalf("extracted only %d ./bin/keyorix invocations from QUICK_START.md; expected at least 8. "+
			"Either the examples were removed (they are the point of the page) or tokenize/"+
			"quickstartInvocations has drifted and this guard is no longer checking anything", len(invocations))
	}

	for _, toks := range invocations {
		// Leading non-flag tokens are the command path; everything after the
		// first flag is arguments or flags.
		var path []string
		for _, tk := range toks {
			if strings.HasPrefix(tk, "-") {
				break
			}
			path = append(path, tk)
		}
		if len(path) == 0 {
			continue // bare `./bin/keyorix --help`
		}

		cmd, _, err := rootCmd.Find(path)
		if err != nil || cmd == nil || cmd == rootCmd {
			t.Errorf("QUICK_START.md documents `keyorix %s`, which is not a command "+
				"(cobra: %v). Fix the doc, or the command was renamed and the doc was not updated.",
				strings.Join(path, " "), err)
			continue
		}

		for _, tk := range toks {
			if !strings.HasPrefix(tk, "--") {
				continue
			}
			name := strings.TrimPrefix(tk, "--")
			if i := strings.Index(name, "="); i >= 0 {
				name = name[:i]
			}
			if name == "" || cobraBuiltinFlags[name] {
				continue
			}
			if lookupFlag(cmd, name) == nil {
				t.Errorf("QUICK_START.md uses `--%s` with `keyorix %s`, but that command has no such flag. "+
					"This is exactly the class of defect this guard exists for: the previous version of "+
					"the page told users to run `share create --recipient <email>` when the flag is "+
					"--recipient-id and takes a uint.", name, strings.Join(path, " "))
			}
		}
	}
}

// lookupFlag resolves a flag against a command's own, persistent, and inherited
// sets, plus the root's persistent flags.
func lookupFlag(cmd *cobra.Command, name string) *pflag.Flag {
	for _, set := range []*pflag.FlagSet{
		cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags(), rootCmd.PersistentFlags(),
	} {
		if set == nil {
			continue
		}
		if f := set.Lookup(name); f != nil {
			return f
		}
	}
	return nil
}
