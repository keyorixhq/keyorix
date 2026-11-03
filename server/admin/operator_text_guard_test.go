package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// Operator text is what `keyorix-server admin` prints: progress lines, errors,
// --help. These guards keep two kinds of mistakes out of it (ADMIN-WORDING-1):
//
//   - a reference to the project's internal design notes or issue tracker
//     ("design §3.4", "design-b3-backup-v2.md", "(#429)"), which means nothing to
//     an operator;
//   - a hint that names a command or flag that does not exist
//     ("run `keyorix-server admin init --storage-type postgres`" when init has no
//     such flag).
//
// Both read the string LITERALS of the non-test Go files of operatorTextDirs
// (comments are not part of the AST, so a design reference in a comment is
// fine). Adjacent literals joined with "+" are folded into one string first, so a
// phrase split across source lines is still seen. What they do not see: a message
// assembled at run time from a variable, a //go:embed file, and text produced by
// packages outside operatorTextDirs.

// operatorTextDirs are the packages whose strings reach the operator through
// the admin commands, relative to this directory.
var operatorTextDirs = []string{
	".",
	"../../internal/backupfmt",
	"../../internal/encryption",
	"../../internal/encryptionops",
}

var (
	internalRefRE = regexp.MustCompile(`design §|design-b[0-9]|#[0-9]{3,5}\b`)
	// adminHintRE finds `keyorix-server admin <words and --flags>` and the short
	// form `admin <words>` when it sits right after a backtick or a quote (plain
	// prose such as "admin access" is not a hint).
	adminHintRE = regexp.MustCompile("(?:keyorix-server |[`'])admin((?:--?[A-Za-z][A-Za-z0-9-]*(?:=[^\\s`'\"]*)?|[a-z][a-z0-9-]*|<[^>]*>|\\[[^\\]]*\\]|\\s)*)")
)

// literal is one string constant found in the source.
type literal struct {
	file string
	line int
	text string
}

// stringLiterals returns every string literal of src (a Go file's contents),
// with "a"+"b" chains folded into one literal.
func stringLiterals(t testing.TB, filename string, src any) []literal {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	require.NoError(t, err)
	var out []literal
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if s, ok := foldConcat(x); ok {
				out = append(out, literal{filename, fset.Position(x.Pos()).Line, s})
				return false
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if s, err := strconv.Unquote(x.Value); err == nil {
					out = append(out, literal{filename, fset.Position(x.Pos()).Line, s})
				}
			}
		}
		return true
	})
	return out
}

// foldConcat evaluates e when it is made only of string literals joined by "+".
func foldConcat(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return foldConcat(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok := foldConcat(x.X)
		if !ok {
			return "", false
		}
		r, ok := foldConcat(x.Y)
		return l + r, ok
	}
	return "", false
}

// operatorLiterals returns the literals of every non-test .go file in dirs.
func operatorLiterals(t testing.TB, dirs []string) []literal {
	t.Helper()
	var out []literal
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		require.NoError(t, err)
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(name) // #nosec G304 -- a fixed list of source directories
			require.NoError(t, err)
			out = append(out, stringLiterals(t, name, src)...)
		}
	}
	return out
}

func internalReferences(lits []literal) []string {
	var found []string
	for _, l := range lits {
		if m := internalRefRE.FindString(l.text); m != "" {
			found = append(found, l.file+":"+strconv.Itoa(l.line)+": "+strconv.Quote(m))
		}
	}
	sort.Strings(found)
	return found
}

// TestOperatorTextHasNoInternalReferences fails when a string literal in the
// admin commands' packages cites "design §…", "design-bN…" or a bare issue/PR
// number. Delete the reference and keep the sentence.
func TestOperatorTextHasNoInternalReferences(t *testing.T) {
	g := guardrules.Rollout(t)
	for _, ref := range internalReferences(operatorLiterals(t, operatorTextDirs)) {
		g.Errorf("%s in operator-facing text: delete the internal design/issue reference and keep the sentence", ref)
	}
}

// TestOperatorTextGuard_CalibrationOnPlantedLiterals proves the matcher both
// ways: red on the three shapes (also when the phrase is split by "+"), green
// on text an operator may see.
func TestOperatorTextGuard_CalibrationOnPlantedLiterals(t *testing.T) {
	red := `package p
import "fmt"
func f() {
	fmt.Println("Loading data (design §3.4)...")
	_ = fmt.Errorf("see docs/design-b2-recover-admin.md for details")
	_ = fmt.Errorf("sets the KEK (#429)")
	_ = fmt.Errorf("split across " +
		"lines (design " + "§7.4)")
}
`
	got := internalReferences(stringLiterals(t, "planted.go", red))
	require.Len(t, got, 4, "got %v", got)

	green := `package p
import "fmt"
// design §3.4 in a comment is not operator text; neither is issue #1234 here.
func f() {
	fmt.Println("Loading data into the staged database...")
	_ = fmt.Errorf("colour #fff and #12 and issue 12345 are fine, and so is design review")
}
`
	require.Empty(t, internalReferences(stringLiterals(t, "clean.go", green)))
}

// ---- hint validity ----------------------------------------------------------

// hint is one `admin ...` command line found in a literal.
type hint struct {
	literal
	words []string // everything after "admin"
}

func adminHints(lits []literal) []hint {
	var out []hint
	for _, l := range lits {
		for _, m := range adminHintRE.FindAllStringSubmatch(l.text, -1) {
			if w := strings.Fields(m[1]); len(w) > 0 {
				out = append(out, hint{l, w})
			}
		}
	}
	return out
}

// resolveHint checks the words of an `admin ...` hint against the command tree
// rooted at root: the subcommand path must exist, and every --flag before a
// placeholder must be a flag of the command it resolves to (its own or an
// inherited one). It returns a description of the first problem, or "".
func resolveHint(root *cobra.Command, words []string) string {
	// `admin version` is answered by Execute before cobra sees the arguments (see
	// admin.go), so it is not in the tree.
	if len(words) == 1 && words[0] == "version" {
		return ""
	}
	cmd := root
	i := 0
	for ; i < len(words); i++ {
		w := words[i]
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "<") || strings.HasPrefix(w, "[") {
			break
		}
		if !cmd.HasSubCommands() {
			break // a positional value of cmd
		}
		sub := findSub(cmd, w)
		if sub == nil {
			return "`" + cmd.CommandPath() + "` has no subcommand " + strconv.Quote(w)
		}
		cmd = sub
	}
	for _, w := range words[i:] {
		if strings.HasPrefix(w, "<") || strings.HasPrefix(w, "[") {
			continue
		}
		if !strings.HasPrefix(w, "-") {
			continue // a value
		}
		name, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
		if name == "help" || name == "h" {
			continue
		}
		var fl *pflag.Flag
		if strings.HasPrefix(w, "--") {
			fl = cmd.Flags().Lookup(name)
			if fl == nil {
				fl = cmd.InheritedFlags().Lookup(name)
			}
		} else if len(name) == 1 {
			fl = cmd.Flags().ShorthandLookup(name)
			if fl == nil {
				fl = cmd.InheritedFlags().ShorthandLookup(name)
			}
		}
		if fl == nil {
			return "`" + cmd.CommandPath() + "` has no flag " + w
		}
	}
	return ""
}

func findSub(cmd *cobra.Command, name string) *cobra.Command {
	for _, c := range cmd.Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return c
		}
	}
	return nil
}

// TestAdminHintsNameRealCommandsAndFlags resolves every "run `keyorix-server
// admin <cmd> --flag`" hint found in the packages' string literals against the
// real cobra tree. SELF_HOSTING once documented `admin init --storage-type`
// before that flag existed; this is the same mistake caught in the program's own
// text. A hint that stops at a <placeholder> is checked up to it.
func TestAdminHintsNameRealCommandsAndFlags(t *testing.T) {
	hints := adminHints(operatorLiterals(t, operatorTextDirs))
	require.NotEmpty(t, hints, "the extractor found no hints at all: it no longer matches the wording")
	t.Logf("checked %d hints", len(hints))
	for _, h := range hints {
		if problem := resolveHint(rootCmd, h.words); problem != "" {
			t.Errorf("%s:%d: hint `admin %s`: %s", h.file, h.line, strings.Join(h.words, " "), problem)
		}
	}
}

// TestAdminHintGuard_Calibration proves the resolver is red on a command that
// does not exist and on a flag that does not exist, and green on the real
// `admin init --storage-type`.
func TestAdminHintGuard_Calibration(t *testing.T) {
	check := func(text string) string {
		hs := adminHints([]literal{{text: text}})
		require.Len(t, hs, 1, text)
		return resolveHint(rootCmd, hs[0].words)
	}
	require.Empty(t, check("run `keyorix-server admin init --storage-type postgres` in a fresh directory"))
	require.Empty(t, check("run 'keyorix-server admin encryption rotate --dry-run'"))
	require.Contains(t, check("run `keyorix-server admin no-such-command`"), "no subcommand")
	require.Contains(t, check("run `keyorix-server admin init --no-such-flag`"), "no flag --no-such-flag")
	require.Contains(t, check("run `keyorix-server admin encryption bogus`"), "no subcommand")
	require.Empty(t, check("run `keyorix-server admin version`"))
	// prose, also inside quotes, is not a hint
	require.Empty(t, adminHints([]literal{{text: "needs admin access to the host"}}))
	require.Empty(t, adminHints([]literal{{text: `("admin password rejected: too short")`}}))
}
