package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newTestCmd() (*cobra.Command, *bytes.Buffer) {
	c := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return nil }}
	var flagVal string
	c.Flags().StringVar(&flagVal, "token", "", "")
	var errBuf bytes.Buffer
	c.SetErr(&errBuf)
	return c, &errBuf
}

func TestReadCredentialFile_FromPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(path, []byte("s3cr3t-token\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := readCredentialFile(path)
	if err != nil {
		t.Fatalf("readCredentialFile: %v", err)
	}
	if got != "s3cr3t-token" {
		t.Errorf("got %q, want trailing newline trimmed", got)
	}
}

func TestReadCredentialFile_FromStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	go func() {
		_, _ = w.Write([]byte("stdin-token\n"))
		_ = w.Close()
	}()

	got, err := readCredentialFile("-")
	if err != nil {
		t.Fatalf("readCredentialFile(\"-\"): %v", err)
	}
	if got != "stdin-token" {
		t.Errorf("got %q, want stdin-token", got)
	}
}

func TestReadCredentialFile_MissingFile(t *testing.T) {
	if _, err := readCredentialFile(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("readCredentialFile on a missing file returned no error")
	}
}

func TestResolveCredential_PlainFlagWinsAndWarns(t *testing.T) {
	c, errBuf := newTestCmd()
	_ = c.Flags().Set("token", "plain-value")

	got, err := resolveCredential(c, "token", "plain-value", "", "KEYORIX_TOKEN")
	if err != nil {
		t.Fatalf("resolveCredential: %v", err)
	}
	if got != "plain-value" {
		t.Errorf("got %q, want plain-value", got)
	}
	if !strings.Contains(errBuf.String(), "--token") {
		t.Errorf("stderr = %q, want a warning naming --token", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "plain-value") {
		t.Error("warning leaked the credential VALUE, not just the flag name")
	}
}

func TestResolveCredential_FileFlagNoWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(path, []byte("file-value"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	c, errBuf := newTestCmd()

	got, err := resolveCredential(c, "token", "", path, "KEYORIX_TOKEN")
	if err != nil {
		t.Fatalf("resolveCredential: %v", err)
	}
	if got != "file-value" {
		t.Errorf("got %q, want file-value", got)
	}
	if errBuf.String() != "" {
		t.Errorf("stderr = %q, want no warning for the --*-file path", errBuf.String())
	}
}

func TestResolveCredential_EnvVarFallback(t *testing.T) {
	t.Setenv("KEYORIX_TOKEN", "env-value")
	c, errBuf := newTestCmd()

	got, err := resolveCredential(c, "token", "", "", "KEYORIX_TOKEN")
	if err != nil {
		t.Fatalf("resolveCredential: %v", err)
	}
	if got != "env-value" {
		t.Errorf("got %q, want env-value", got)
	}
	if errBuf.String() != "" {
		t.Errorf("stderr = %q, want no warning for the env-var path", errBuf.String())
	}
}

func TestWarnInsecureFlag_OnlyWarnsWhenFlagChanged(t *testing.T) {
	c, errBuf := newTestCmd()
	warnInsecureFlag(c, "token", "advice")
	if errBuf.String() != "" {
		t.Errorf("warned for an unchanged flag: %q", errBuf.String())
	}

	_ = c.Flags().Set("token", "x")
	warnInsecureFlag(c, "token", "advice")
	if !strings.Contains(errBuf.String(), "--token") {
		t.Errorf("stderr = %q, want a warning naming --token after the flag was set", errBuf.String())
	}
}
