// secret_test.go — the security-critical regression guard for PR 5: secret values
// (a new value passed to rotate, a value read from an import file and sent to the
// server) must never reach stdout or stderr except through their one legitimate path.
// Mirrors PR 4's identical canary-value discipline (secret_test.go in that PR).
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	_ = w.Close()
	buf, _ := io.ReadAll(r)
	return string(buf)
}

// captureStdoutAndStderr runs fn with both stdout and stderr redirected and returns
// each independently.
func captureStdoutAndStderr(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	stdout = captureStdout(t, func() {
		stderr = captureStderr(t, fn)
	})
	return stdout, stderr
}

const secretCanaryValue = "CANARY-VALUE-kx9f7a2e1b8c-do-not-log-me"

// TestSecretRotate_NeverLeaksTheCanaryValue runs `secret rotate --value <canary>`
// against an httptest server and asserts the canary never appears on stdout or
// stderr — only the insecure-flag WARNING TEXT (which names the flag, never its
// value) is expected on stderr.
func TestSecretRotate_NeverLeaksTheCanaryValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"ID":1,"Name":"canary-secret"}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	rotateID = 1
	rotateValue = secretCanaryValue
	defer func() { rotateID, rotateValue = 0, "" }()

	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&rotateValue, "value", "", "")
	_ = cmd.Flags().Set("value", secretCanaryValue)

	stdout, stderr := captureStdoutAndStderr(t, func() {
		if err := runSecretRotate(cmd, nil); err != nil {
			t.Fatalf("runSecretRotate: %v", err)
		}
	})
	if containsAll(stderr, secretCanaryValue) {
		t.Fatalf("canary value leaked to stderr: %q", stderr)
	}
	if containsAll(stdout, secretCanaryValue) {
		t.Fatalf("canary value leaked to stdout (rotate must never echo the value back): %q", stdout)
	}
}

// TestSecretImport_NeverLeaksTheCanaryValue imports a one-line dotenv file whose
// value is the canary, and asserts the canary never appears on stdout or stderr —
// only the "+ Imported NAME (id=N)" success line (name, not value).
func TestSecretImport_NeverLeaksTheCanaryValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"data":{"ID":1,"Name":"CANARY_KEY"}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	dir := t.TempDir()
	envFile := filepath.Join(dir, "canary.env")
	if err := os.WriteFile(envFile, []byte("CANARY_KEY="+secretCanaryValue+"\n"), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	importFile = envFile
	importFormat = "dotenv"
	importProject = 1
	importEnv = 1
	importDryRun = false
	importSkipExisting = true
	defer func() {
		importFile, importFormat = "", "dotenv"
		importProject, importEnv = 0, 0
	}()

	cmd := &cobra.Command{}
	stdout, stderr := captureStdoutAndStderr(t, func() {
		if err := runSecretImport(cmd, nil); err != nil {
			t.Fatalf("runSecretImport: %v", err)
		}
	})
	if containsAll(stderr, secretCanaryValue) {
		t.Fatalf("canary value leaked to stderr: %q", stderr)
	}
	if containsAll(stdout, secretCanaryValue) {
		t.Fatalf("canary value leaked to stdout (import must never echo the value back): %q", stdout)
	}
	if !containsAll(stdout, "Imported", "CANARY_KEY") {
		t.Fatalf("expected the import success line naming the key (not the value), got: %q", stdout)
	}
}

// TestSecretImport_DryRunNeverLeaksTheCanaryValue covers the --dry-run preview path
// separately: it deliberately prints byte-length, not content, and must never
// regress to printing a value prefix.
func TestSecretImport_DryRunNeverLeaksTheCanaryValue(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "canary.env")
	if err := os.WriteFile(envFile, []byte("CANARY_KEY="+secretCanaryValue+"\n"), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	importFile = envFile
	importFormat = "dotenv"
	importProject = 1
	importEnv = 1
	importDryRun = true
	defer func() {
		importFile, importFormat = "", "dotenv"
		importProject, importEnv = 0, 0
		importDryRun = false
	}()

	cmd := &cobra.Command{}
	stdout, stderr := captureStdoutAndStderr(t, func() {
		if err := runSecretImport(cmd, nil); err != nil {
			t.Fatalf("runSecretImport: %v", err)
		}
	})
	if containsAll(stderr, secretCanaryValue) || containsAll(stdout, secretCanaryValue) {
		t.Fatalf("canary value leaked in dry-run output: stdout=%q stderr=%q", stdout, stderr)
	}
	if !containsAll(stdout, "CANARY_KEY", "bytes>") {
		t.Fatalf("expected dry-run to show the key name and a byte count, got: %q", stdout)
	}
}

func TestWarnInsecureFlag_NeverPrintsTheValue(t *testing.T) {
	const canary = "CANARY-do-not-print-me"
	var v string
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&v, "value", "", "")
	_ = cmd.Flags().Set("value", canary)

	stderr := captureStderr(t, func() {
		warnInsecureFlag(cmd, "value", "use --interactive instead.")
	})
	if containsAll(stderr, canary) {
		t.Fatalf("warnInsecureFlag must never print the flag's value, got: %q", stderr)
	}
	if !containsAll(stderr, "--value", "insecure") {
		t.Fatalf("warnInsecureFlag output missing expected warning text, got: %q", stderr)
	}
}
