package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// findCommand returns the command at the given path ("secret import"), or fails.
func findCommand(t *testing.T, path string) *cobra.Command {
	t.Helper()
	c, _, err := rootCmd.Find(strings.Fields(path))
	if err != nil || c == nil || c.CommandPath() != "keyorix "+path {
		t.Fatalf("no command %q (found %v, err %v)", path, c, err)
	}
	return c
}

// #4280: login --help told the reader to "Pass --mfa-code", a flag the CLI refuses
// (secretflags.go). The help must name the supported ways.
func TestLoginHelpNamesTheMFACodeEnvVars(t *testing.T) {
	long := findCommand(t, "login").Long
	for _, want := range []string{"KEYORIX_MFA_CODE", "KEYORIX_MFA_CODE_FILE"} {
		if !strings.Contains(long, want) {
			t.Errorf("login --help does not name %s:\n%s", want, long)
		}
	}
	if strings.Contains(strings.Join(strings.Fields(long), " "), "Pass --mfa-code") {
		t.Errorf("login --help still tells the reader to pass the refused --mfa-code flag")
	}
}

// Family guard: no command's long help may tell the reader to pass a flag that the CLI
// refuses (refusedSecretFlags). It checks the "Pass --x" and "use --x" phrasings.
func TestNoHelpAdvisesARefusedSecretFlag(t *testing.T) {
	for _, sf := range refusedSecretFlags {
		// Help text is hard-wrapped: compare on one line so "Pass\n--x" is caught too.
		long := strings.Join(strings.Fields(findCommand(t, sf.Command).Long), " ")
		for _, lead := range []string{"Pass --", "pass --", "Use --", "use --"} {
			if strings.Contains(long, lead+sf.Flag+" ") {
				t.Errorf("%s --help advises %q, a flag the CLI refuses", sf.Command, lead+sf.Flag)
			}
		}
	}
}

// #4280: `secret import --help` sent the reader to "the old CLI's secret import --source".
func TestSecretImportHelpPointsAtKeyorixMigrate(t *testing.T) {
	long := findCommand(t, "secret import").Long
	for _, want := range []string{"keyorix-migrate", "docs/migrate-from-vault.md", "docs/migrate-from-cloud.md"} {
		if !strings.Contains(long, want) {
			t.Errorf("secret import --help does not mention %s:\n%s", want, long)
		}
	}
	if strings.Contains(long, "old CLI") {
		t.Errorf("secret import --help still points at the old CLI")
	}
}

// helpTextOf is everything `keyorix <cmd> --help` prints that a person wrote: the short
// and long description, the examples and the usage line of every flag shown.
func helpTextOf(c *cobra.Command) string {
	var b strings.Builder
	b.WriteString(c.Short + "\n" + c.Long + "\n" + c.Example + "\n")
	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if !f.Hidden {
			b.WriteString(f.Usage + "\n")
		}
	})
	return strings.Join(strings.Fields(b.String()), " ")
}

// removedFlagNames are the flag names no command accepts any more: every flag the CLI
// refuses (refusedSecretFlags), unless some command still exposes a flag of that name.
func removedFlagNames(t *testing.T) []string {
	t.Helper()
	applySecretFlagPolicy()
	live := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if !f.Hidden {
				live[f.Name] = true
			}
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(rootCmd)
	seen := map[string]bool{}
	var out []string
	for _, sf := range refusedSecretFlags {
		if !live[sf.Flag] && !seen[sf.Flag] {
			seen[sf.Flag] = true
			out = append(out, sf.Flag)
		}
	}
	return out
}

// Family guard (PILOT-BOOTSTRAP-CLI-1, #4280 follow-up): no command's help may name a
// flag the CLI no longer accepts. A reader who copies "--mfa-code" from `login --help`
// gets a refusal, so the help names the environment variable instead.
func TestNoHelpNamesARemovedFlag(t *testing.T) {
	removed := removedFlagNames(t)
	if len(removed) == 0 {
		t.Fatal("no removed flag names found; the guard is vacuous")
	}
	for _, c := range leafCommands(rootCmd) {
		text := helpTextOf(c)
		for _, name := range removed {
			if i := strings.Index(text, "--"+name); i >= 0 {
				rest := text[i+len(name)+2:]
				if rest == "" || !(rest[0] == '-' || rest[0] >= 'a' && rest[0] <= 'z' || rest[0] >= '0' && rest[0] <= '9') {
					t.Errorf("%s --help names the removed flag --%s", commandKey(c), name)
				}
			}
		}
	}
}
