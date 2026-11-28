package cmd

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// refusedFlagNames is every flag name in refusedSecretFlags (--password, --mfa-code,
// --value, ...). Derived from the table, not copied, so a newly refused flag is
// covered the day it is added.
func refusedFlagNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, sf := range refusedSecretFlags {
		if !seen[sf.Flag] {
			seen[sf.Flag] = true
			names = append(names, sf.Flag)
		}
	}
	sort.Strings(names)
	return names
}

// refusedFlagMentions renders c's help and returns one entry per line that names a
// refused flag the command does not itself offer as a visible flag. A hidden flag is
// not offered: the policy refuses it, so help must not send anyone to it. The name
// must end at a flag boundary, so --url does not match --url-file.
func refusedFlagMentions(c *cobra.Command, names []string) []string {
	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetErr(&buf)
	defer func() { c.SetOut(nil); c.SetErr(nil) }()
	_ = c.Help()

	var hits []string
	for _, name := range names {
		if f := c.Flags().Lookup(name); f != nil && !f.Hidden {
			continue // this command really takes it
		}
		re := regexp.MustCompile(`--` + regexp.QuoteMeta(name) + `(?:[^-\w]|$)`)
		for _, line := range strings.Split(buf.String(), "\n") {
			if re.MatchString(line) {
				hits = append(hits, "--"+name+": "+strings.TrimSpace(line))
			}
		}
	}
	return hits
}

// TestHelpNamesNoRefusedFlag: the help of every command (the first-run ones, keyorix,
// login, system init and secret create, and the rest of the tree) only shows what
// works. A flag that applySecretFlagPolicy hides and refuses must not be named in a
// description, an example or the long text: the reader would type it and be refused.
// The safe way in is named instead (stdin, --from-file, KEYORIX_*[_FILE]).
func TestHelpNamesNoRefusedFlag(t *testing.T) {
	applySecretFlagPolicy()
	names := refusedFlagNames()
	if len(names) == 0 {
		t.Fatal("no refused flags: refusedSecretFlags is empty, the scan would check nothing")
	}

	checked := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		checked++
		for _, hit := range refusedFlagMentions(c, names) {
			t.Errorf("%q help names a refused flag (%s): name the stdin / file / KEYORIX_* way in instead", c.CommandPath(), hit)
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(rootCmd)

	for _, must := range []string{"keyorix", "keyorix login", "keyorix system init", "keyorix secret create"} {
		c, _, err := rootCmd.Find(strings.Fields(must)[1:])
		if err != nil || c.CommandPath() != must {
			t.Errorf("%q is not in the command tree (found %v, err %v): the scan would skip a first-run command", must, c, err)
		}
	}
	t.Logf("scanned the help of %d commands for %d refused flag names", checked, len(names))
}

// TestRefusedFlagScanFires is the scan's own red case: help that names a refused flag
// is reported, a flag boundary is respected, and a flag the command really offers is
// not reported.
func TestRefusedFlagScanFires(t *testing.T) {
	names := []string{"mfa-code", "url"}

	// Cobra prints the usage block (flags, examples) only for a runnable command.
	run := func(*cobra.Command, []string) {}
	planted := &cobra.Command{Use: "planted", Short: "planted", Run: run, Long: "Pass the code with --mfa-code 123456.", Example: "  planted --url=https://x"}
	if got := refusedFlagMentions(planted, names); len(got) != 2 {
		t.Fatalf("planted help: got %v, want a hit for --mfa-code and for --url", got)
	}

	boundary := &cobra.Command{Use: "boundary", Short: "boundary", Run: run, Long: "Use --url-file <path>, not the other."}
	if got := refusedFlagMentions(boundary, names); len(got) != 0 {
		t.Fatalf("--url-file reported as --url: %v", got)
	}

	offered := &cobra.Command{Use: "offered", Short: "offered", Run: run}
	offered.Flags().String("mfa-code", "", "the code, e.g. --mfa-code")
	if got := refusedFlagMentions(offered, names); len(got) != 0 {
		t.Fatalf("a visible flag of the command itself was reported: %v", got)
	}

	hidden := &cobra.Command{Use: "hidden", Short: "hidden", Run: run, Long: "Pass --mfa-code."}
	hidden.Flags().String("mfa-code", "", "")
	_ = hidden.Flags().MarkHidden("mfa-code")
	if got := refusedFlagMentions(hidden, names); len(got) == 0 {
		t.Fatal("a hidden flag counted as offered: help may name it")
	}
}

// TestFlagUsageHasNoBacktickPlaceholder: cobra reads the first `backquoted` word of a
// flag's usage as its value placeholder, so a command written in backticks inside a
// description turns up in --help as the flag's type ("--environment keyorix project
// environments <project-id>"). Quote it with plain quotes instead.
func TestFlagUsageHasNoBacktickPlaceholder(t *testing.T) {
	applySecretFlagPolicy()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if !f.Hidden && strings.Contains(f.Usage, "`") {
				t.Errorf("%q --%s: usage contains a backtick, which cobra prints as the flag's value name: %q", c.CommandPath(), f.Name, f.Usage)
			}
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(rootCmd)
}
