package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// leafCommands returns every runnable leaf below root, excluding cobra's own
// generated `help` and `completion` trees, and its hidden `__complete` /
// `__completeNoDesc` commands (added to rootCmd by any test that exercises shell
// completion, so their presence depends on test order).
func leafCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && (c.Name() == "help" || c.Name() == "completion" ||
			c.Name() == cobra.ShellCompRequestCmd || c.Name() == cobra.ShellCompNoDescRequestCmd) {
			return
		}
		if !c.HasAvailableSubCommands() {
			out = append(out, c)
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return out
}

func commandKey(c *cobra.Command) string {
	return strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")
}

// splitExampleLine splits one example line into words, honouring double quotes, and
// drops a trailing shell redirect ("> file").
func splitExampleLine(line string) []string {
	var words []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote, have = !inQuote, true
		case r == ' ' && !inQuote:
			if have {
				words = append(words, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		words = append(words, cur.String())
	}
	for i, w := range words {
		if w == ">" {
			return words[:i]
		}
	}
	return words
}

// flagsThatCarrySecrets are the flags no example may demonstrate: a secret value on
// the command line ends up in shell history and `ps` output.
var flagsThatCarrySecrets = map[string]bool{
	"value": true, "password": true, "current-password": true, "new-password": true,
	"admin-password": true, "bootstrap-token": true, "mfa-code": true, "code": true,
}

// TestHelpExamples_EveryLeafHasAValidExample is the guard behind helpExamples: it
// fails when a command is added without an example, when an entry outlives its
// command, and when an example uses a flag the command no longer has (or hands a
// secret to the command line).
func TestHelpExamples_EveryLeafHasAValidExample(t *testing.T) {
	applyHelpExamples()

	leaves := leafCommands(rootCmd)
	if len(leaves) < 200 {
		t.Fatalf("only %d leaf commands found; the walk is broken", len(leaves))
	}
	known := map[string]bool{}
	for _, c := range leaves {
		key := commandKey(c)
		known[key] = true
		if strings.TrimSpace(c.Example) == "" {
			t.Errorf("%q has no Example: add it to helpExamples (help_examples.go)", key)
			continue
		}
		for line := range strings.SplitSeq(c.Example, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			words := splitExampleLine(line)
			if len(words) == 0 || words[0] != "keyorix" {
				// A command's own hand-written Example may show other tools.
				if _, ours := helpExamples[key]; ours {
					t.Errorf("%q example line must start with \"keyorix\": %q", key, line)
				}
				continue
			}
			found, _, err := rootCmd.Find(words[1:])
			if err != nil || found != c {
				t.Errorf("%q example runs a different command (%v): %q", key, found.CommandPath(), line)
				continue
			}
			for _, w := range words[1:] {
				if w == "--" {
					break
				}
				if !strings.HasPrefix(w, "--") {
					continue
				}
				name, _, _ := strings.Cut(strings.TrimPrefix(w, "--"), "=")
				f := c.Flags().Lookup(name)
				if f == nil {
					f = c.InheritedFlags().Lookup(name)
				}
				if f == nil {
					t.Errorf("%q example uses unknown flag --%s: %q", key, name, line)
				} else if f.Deprecated != "" {
					t.Errorf("%q example teaches the deprecated flag --%s (%s): %q", key, name, f.Deprecated, line)
				}
				if flagsThatCarrySecrets[name] {
					t.Errorf("%q example puts a secret on the command line (--%s): %q", key, name, line)
				}
			}
		}
	}

	var stale []string
	for key := range helpExamples {
		if !known[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("helpExamples has an entry for %q, which is not a command", key)
	}
}

// builtinRoleNamesFromServerSource returns the keys of builtinRoleNames in
// internal/core/auth_bootstrap.go, the single source of truth for the roles that
// ship with the product. The CLI module must not import internal/core (see
// cli/internal/depguard), so the names are read from the source file with
// go/parser instead of copied into the CLI, where the copy would rot.
func builtinRoleNamesFromServerSource(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "core", "auth_bootstrap.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("cannot parse %s for the built-in role names: %v", path, err)
	}
	names := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "builtinRoleNames" || len(spec.Values) != 1 {
			return true
		}
		lit, ok := spec.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if b, ok := kv.Key.(*ast.BasicLit); ok && b.Kind == token.STRING {
				if name, err := strconv.Unquote(b.Value); err == nil {
					names[name] = true
				}
			}
		}
		return false
	})
	if !names["project_developer"] || !names["system_admin"] {
		t.Fatalf("builtinRoleNames not found in %s (got %d names): the guard would be vacuous", path, len(names))
	}
	return names
}

// TestHelpExamples_RoleValuesAreBuiltinRoles: a help example whose --role value is
// not a real role fails the first time a user pastes it ("role \"developer\" not
// found"). Every --role value in every command's Example must be a built-in role
// name. A role the example's own text creates first is not supported here on
// purpose: examples should run as written against a fresh install.
func TestHelpExamples_RoleValuesAreBuiltinRoles(t *testing.T) {
	applyHelpExamples()
	builtin := builtinRoleNamesFromServerSource(t)

	checked := 0
	for _, c := range leafCommands(rootCmd) {
		for line := range strings.SplitSeq(c.Example, "\n") {
			words := splitExampleLine(strings.TrimSpace(line))
			for i, w := range words {
				var role string
				switch {
				case w == "--role" && i+1 < len(words):
					role = words[i+1]
				case strings.HasPrefix(w, "--role="):
					role = strings.TrimPrefix(w, "--role=")
				default:
					continue
				}
				checked++
				if !builtin[role] {
					t.Errorf("%q example uses --role %s, which is not a built-in role (internal/core/auth_bootstrap.go builtinRoleNames): %q",
						commandKey(c), role, strings.TrimSpace(line))
				}
			}
		}
	}
	if checked < 8 {
		t.Fatalf("only %d --role examples found; the walk is broken (the CLI has at least 8)", checked)
	}
}
