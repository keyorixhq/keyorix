package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// #2938: after a runtime failure (403, 409, wrong password) cobra used to print the
// error, then the whole usage/flags block, then main() printed the error again, so
// the real message scrolled away. A runtime failure prints no usage and no error
// of its own (main prints it once); a flag mistake still prints usage.

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	defer func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		loginCmd.SilenceUsage = false // PersistentPreRun sets it on the shared command object
	}()
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestRuntimeFailureDoesNotDumpUsage(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1") // nothing listens: a runtime failure after flag parsing
	t.Setenv("KEYORIX_TOKEN", "tok")
	out, err := runRoot(t, "login", "--server", "http://127.0.0.1:1", "--username", "u", "--password", "p")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(out, "Usage:") || strings.Contains(out, "Flags:") {
		t.Fatalf("runtime failure printed the usage block:\n%s", out)
	}
	if strings.Contains(out, "Error:") {
		t.Fatalf("cobra printed the error itself (main() prints it once):\n%s", out)
	}
}

func TestFlagMistakeStillPrintsUsage(t *testing.T) {
	out, err := runRoot(t, "login", "--no-such-flag")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("flag error should still show usage:\n%s", out)
	}
}
