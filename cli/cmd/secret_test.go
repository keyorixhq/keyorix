package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what
// was written. Mirrors pat_test.go's captureStdout.
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

// captureStdoutAndStderr runs fn with both stdout and stderr redirected and
// returns each independently -- for TestNoSecretCommandLeaksTheCanaryValue,
// which needs to assert on stderr specifically (never) and, for the one
// legitimate case (get --show-value), on stdout (only there, by design).
func captureStdoutAndStderr(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	stdout = captureStdout(t, func() {
		stderr = captureStderr(t, fn)
	})
	return stdout, stderr
}

// secretCanaryServer returns an httptest server that accepts any secret
// mutation and echoes back a response that never includes the request body
// (matching the real server: CreateSecret/UpdateSecret responses are the
// secret's metadata only, never its value).
func secretCanaryServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets":
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"data":{"ID":1,"Name":"canary-secret","Type":"generic","ProjectID":1,"EnvironmentID":1}}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/1":
			_, _ = fmt.Fprint(w, `{"data":{"ID":1,"Name":"canary-secret","Type":"generic"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestNoSecretCommandLeaksTheCanaryValue is the standing regression guard
// this package's own doc comment (secret.go) promises: a distinctive canary
// value passed via --value to create/update must never appear on stderr (an
// error message, a warning, a log line) -- only the insecure-flag WARNING
// TEXT (which names the flag, never its value) is expected there. This
// guards CWE-532 (sensitive data in log files) and the argv/log-echo
// scenarios docs/cli-split-inventory.md's PR 4 instruction calls out by name.
func TestNoSecretCommandLeaksTheCanaryValue(t *testing.T) {
	const canary = "CANARY-VALUE-kx9f7a2e1b8c-do-not-log-me"
	srv := secretCanaryServer(t)
	setPATCreds(t, srv)

	t.Run("create --value", func(t *testing.T) {
		secretCreateName = "canary-secret"
		secretCreateValue = canary
		secretCreateType = "generic"
		secretCreateProjectID = 1
		secretCreateEnvironmentID = 1
		defer func() {
			secretCreateName, secretCreateValue = "", ""
			secretCreateType, secretCreateProjectID, secretCreateEnvironmentID = "generic", 1, 1
		}()

		stdout, stderr := captureStdoutAndStderr(t, func() {
			if err := runSecretCreate(secretCreateCmd, nil); err != nil {
				t.Fatalf("runSecretCreate: %v", err)
			}
		})
		if containsAll(stderr, canary) {
			t.Fatalf("canary value leaked to stderr: %q", stderr)
		}
		if containsAll(stdout, canary) {
			t.Fatalf("canary value leaked to stdout (create must never echo the value back): %q", stdout)
		}
	})

	t.Run("update --value", func(t *testing.T) {
		secretUpdateID = 1
		secretUpdateValue = canary
		defer func() { secretUpdateID, secretUpdateValue = 0, "" }()

		stdout, stderr := captureStdoutAndStderr(t, func() {
			if err := runSecretUpdate(secretUpdateCmd, nil); err != nil {
				t.Fatalf("runSecretUpdate: %v", err)
			}
		})
		if containsAll(stderr, canary) {
			t.Fatalf("canary value leaked to stderr: %q", stderr)
		}
		if containsAll(stdout, canary) {
			t.Fatalf("canary value leaked to stdout (update must never echo the value back): %q", stdout)
		}
	})
}

// TestSecretGet_ShowValueOnlyReachesStdout is the counterpart to the canary
// test above: `secret get --show-value` legitimately prints the decrypted
// value -- but only to stdout, on purpose, never to stderr.
func TestSecretGet_ShowValueOnlyReachesStdout(t *testing.T) {
	const canary = "CANARY-VALUE-kx9f7a2e1b8c-do-not-log-me"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"secret":{"ID":1,"Name":"canary-secret","Type":"generic"},"value":%q}}`, canary)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	secretGetID = 1
	secretGetShowValue = true
	defer func() { secretGetID, secretGetShowValue = 0, false }()

	stdout, stderr := captureStdoutAndStderr(t, func() {
		if err := runSecretGet(secretGetCmd, nil); err != nil {
			t.Fatalf("runSecretGet: %v", err)
		}
	})
	if !containsAll(stdout, canary) {
		t.Fatalf("expected the canary value on stdout with --show-value, got: %q", stdout)
	}
	if containsAll(stderr, canary) {
		t.Fatalf("canary value leaked to stderr (must only ever reach stdout): %q", stderr)
	}
}

// TestSecretGet_DefaultHidesValue asserts the "value hidden by default"
// parity requirement: without --show-value, GET never requests
// include_value, and the value never appears anywhere in the output.
func TestSecretGet_DefaultHidesValue(t *testing.T) {
	const canary = "CANARY-VALUE-kx9f7a2e1b8c-do-not-log-me"
	var gotIncludeValue string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIncludeValue = r.URL.Query().Get("include_value")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"ID":1,"Name":"canary-secret","Type":"generic","Status":"active"}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	secretGetID = 1
	secretGetShowValue = false
	defer func() { secretGetID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretGet(secretGetCmd, nil); err != nil {
			t.Fatalf("runSecretGet: %v", err)
		}
	})
	if gotIncludeValue == "true" {
		t.Fatal("GET request sent include_value=true without --show-value")
	}
	if containsAll(out, canary) {
		t.Fatalf("value leaked without --show-value: %q", out)
	}
	if !containsAll(out, "Use --show-value to display the decrypted value.") {
		t.Fatalf("output missing the old CLI's exact hidden-value prompt, got: %q", out)
	}
}

// ── golden-output / flag-validation coverage ────────────────────────────────────

func TestRunSecretCreate_RequiresName(t *testing.T) {
	secretCreateName = ""
	secretCreateValue = "x"
	defer func() { secretCreateValue = "" }()
	if err := runSecretCreate(secretCreateCmd, nil); err == nil {
		t.Fatal("expected an error when --name is omitted")
	}
}

func TestRunSecretCreate_RequiresValue(t *testing.T) {
	secretCreateName = "x"
	secretCreateValue, secretCreateFromFile = "", ""
	defer func() { secretCreateName = "" }()
	if err := runSecretCreate(secretCreateCmd, nil); err == nil {
		t.Fatal("expected an error when no value source is given")
	}
}

func TestRunSecretCreate_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretCanaryServer(t)
	setPATCreds(t, srv)
	secretCreateName, secretCreateValue = "canary-secret", "v"
	secretCreateType, secretCreateProjectID, secretCreateEnvironmentID = "generic", 1, 1
	defer func() {
		secretCreateName, secretCreateValue = "", ""
		secretCreateType, secretCreateProjectID, secretCreateEnvironmentID = "generic", 1, 1
	}()

	out := captureStdout(t, func() {
		if err := runSecretCreate(secretCreateCmd, nil); err != nil {
			t.Fatalf("runSecretCreate: %v", err)
		}
	})
	if !containsAll(out, "Secret created successfully!", "ID:", "1", "Name:", "canary-secret") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretDelete_RequiresIDOrName(t *testing.T) {
	secretDeleteID, secretDeleteName = 0, ""
	if err := runSecretDelete(secretDeleteCmd, nil); err == nil {
		t.Fatal("expected an error when neither --id nor --name is given")
	}
}

func TestRunSecretList_EmptyPrintsNoSecretsMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secrets":[],"total":0,"page":1,"page_size":50}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	secretListLimit = 50
	secretListFormat = "table"

	out := captureStdout(t, func() {
		if err := runSecretList(secretListCmd, nil); err != nil {
			t.Fatalf("runSecretList: %v", err)
		}
	})
	if !containsAll(out, "No secrets found.") {
		t.Fatalf("output missing the empty-state message, got: %q", out)
	}
}

func TestRunSecretList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secrets":[{"ID":7,"Name":"db-pass","Type":"generic","Status":"active","CreatedAt":"2026-01-02T00:00:00Z"}],"total":1,"page":1,"page_size":50}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	secretListLimit = 50
	secretListFormat = "table"

	out := captureStdout(t, func() {
		if err := runSecretList(secretListCmd, nil); err != nil {
			t.Fatalf("runSecretList: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "TYPE", "STATUS", "7", "db-pass", "generic", "active") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretUpdate_RequiresID(t *testing.T) {
	secretUpdateID = 0
	if err := runSecretUpdate(secretUpdateCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
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
