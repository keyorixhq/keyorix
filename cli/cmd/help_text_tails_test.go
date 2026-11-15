package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
