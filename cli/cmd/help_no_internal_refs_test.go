package cmd

import (
	"regexp"
	"testing"

	"github.com/spf13/cobra"
)

// internalRefRE matches the project's own bookkeeping: an ADR number, an issue or PR
// number, a design-section sign, an invariant id, an audit "Finding", or the internal
// CLI-split notes. None of them means anything to the person reading `--help`.
var internalRefRE = regexp.MustCompile(`ADR-[0-9]|#[0-9]{3,}|§|\bINV-[A-Z]|\bFinding [A-Z]?[0-9]|cli-split-inventory|\bdesign-b[0-9]`)

// TestHelpTextHasNoInternalReferences (DEMO-COPY-LEFTOVERS-NOV-1, #3744 item 6) is a
// family guard over every command of the tree: the short and long description, the
// examples and the usage line of every visible flag carry no internal reference.
// It reads what a person wrote for --help (helpTextOf); it does not see text printed
// at run time, which the per-command output tests pin.
func TestHelpTextHasNoInternalReferences(t *testing.T) {
	checked := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		checked++
		if m := internalRefRE.FindString(helpTextOf(c)); m != "" {
			t.Errorf("%s --help carries the internal reference %q; say it in plain words", c.CommandPath(), m)
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(rootCmd)
	if checked < 50 {
		t.Fatalf("walked only %d commands; the guard is not seeing the command tree", checked)
	}
}

// TestInternalRefRECatchesEachShape: the guard is red on a planted line of every shape
// it claims to catch, and green on ordinary help text.
func TestInternalRefRECatchesEachShape(t *testing.T) {
	for _, planted := range []string{
		"Send invitations (ADR-024).",
		"refused since #3546",
		"see design §3.4",
		"the INV-CLI-03 rule",
		"Finding S12",
		"Finding 7",
		"docs/cli-split-inventory.md",
		"per design-b3-backup-v2",
	} {
		if !internalRefRE.MatchString(planted) {
			t.Errorf("internalRefRE does not catch %q", planted)
		}
	}
	for _, ordinary := range []string{
		"Send, list, resend, and revoke project invitations.",
		"Resends are rate-limited.",
		"Use #1 as the first example or a 12 char id",
		"See docs/migrate-from-vault.md",
	} {
		if m := internalRefRE.FindString(ordinary); m != "" {
			t.Errorf("internalRefRE flags ordinary text %q (matched %q)", ordinary, m)
		}
	}
}
