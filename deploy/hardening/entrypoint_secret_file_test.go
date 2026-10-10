package hardening

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The container entrypoint (server/entrypoint.sh) reads two secrets itself for the
// optional first-boot admin bootstrap: KEYORIX_ADMIN_PASSWORD and
// KEYORIX_BOOTSTRAP_TOKEN. DEPLOY-2 gives them the same <NAME>_FILE rules the server
// applies to its own secrets (internal/secretenv): X_FILE read with one trailing
// newline stripped; X and X_FILE both set, or an unreadable/empty file, is fatal;
// no value ever appears in a message. The block between the BEGIN/END markers is
// extracted verbatim and run under sh, so this exercises the shipped code.
func secretResolutionBlock(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "server", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	const begin, end = "# --- BEGIN secret-file resolution", "# --- END secret-file resolution"
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatalf("entrypoint.sh has no %q ... %q block", begin, end)
	}
	return s[i:j]
}

// runResolution runs the block, then prints NAME=<value> for the two secrets, and
// returns stdout, stderr and the exit status.
func runResolution(t *testing.T, env map[string]string) (string, string, int) {
	t.Helper()
	script := secretResolutionBlock(t) + `
printf 'PW=[%s]\n' "${KEYORIX_ADMIN_PASSWORD:-}"
printf 'TOK=[%s]\n' "${KEYORIX_BOOTSTRAP_TOKEN:-}"
`
	cmd := exec.Command("sh", "-c", "set -e\n"+script) //nolint:gosec // fixed shell, script from the repo
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), code
}

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEntrypoint_SecretFile_ReadsAndTrimsOneNewline(t *testing.T) {
	cases := map[string]string{
		"pass\n":       "pass",
		"pass\r\n":     "pass",
		"pass":         "pass",
		"pass\n\n":     "pass\n",
		" sp ace \n":   " sp ace ",
		"a\"b\\c$d`e'": "a\"b\\c$d`e'", // shell metacharacters survive untouched
	}
	for content, want := range cases {
		out, errOut, code := runResolution(t, map[string]string{
			"KEYORIX_ADMIN_PASSWORD_FILE": writeTmp(t, content),
			"KEYORIX_BOOTSTRAP_TOKEN":     "tok",
		})
		if code != 0 {
			t.Fatalf("content %q: exit %d, stderr %q", content, code, errOut)
		}
		if !strings.Contains(out, "PW=["+want+"]\n") {
			t.Errorf("content %q: want PW=[%s], got %q", content, want, out)
		}
		if !strings.Contains(out, "TOK=[tok]") {
			t.Errorf("content %q: the plain-env secret must be left alone, got %q", content, out)
		}
	}
}

func TestEntrypoint_SecretFile_BothSetIsFatal(t *testing.T) {
	_, errOut, code := runResolution(t, map[string]string{
		"KEYORIX_BOOTSTRAP_TOKEN":      "env-token-value",
		"KEYORIX_BOOTSTRAP_TOKEN_FILE": writeTmp(t, "file-token-value\n"),
	})
	if code == 0 {
		t.Fatal("both X and X_FILE set must be fatal")
	}
	if !strings.Contains(errOut, "KEYORIX_BOOTSTRAP_TOKEN") || !strings.Contains(errOut, "KEYORIX_BOOTSTRAP_TOKEN_FILE") {
		t.Errorf("message must name both variables, got %q", errOut)
	}
	if strings.Contains(errOut, "env-token-value") || strings.Contains(errOut, "file-token-value") {
		t.Errorf("message must not contain a secret value: %q", errOut)
	}
}

func TestEntrypoint_SecretFile_UnreadableOrEmptyIsFatal(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"missing": {"KEYORIX_ADMIN_PASSWORD_FILE": filepath.Join(t.TempDir(), "nope")},
		"empty":   {"KEYORIX_ADMIN_PASSWORD_FILE": writeTmp(t, "")},
		"newline": {"KEYORIX_ADMIN_PASSWORD_FILE": writeTmp(t, "\n")},
		"dir":     {"KEYORIX_ADMIN_PASSWORD_FILE": t.TempDir()},
	} {
		_, errOut, code := runResolution(t, env)
		if code == 0 {
			t.Errorf("%s: must be fatal, not a fall-through to 'no admin password'", name)
		}
		if !strings.Contains(errOut, "KEYORIX_ADMIN_PASSWORD_FILE") {
			t.Errorf("%s: message must name the variable, got %q", name, errOut)
		}
	}
}

func TestEntrypoint_SecretFile_NeitherSetIsFine(t *testing.T) {
	out, errOut, code := runResolution(t, map[string]string{})
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "PW=[]") || !strings.Contains(out, "TOK=[]") {
		t.Errorf("got %q", out)
	}
}

func TestEntrypoint_SecretFile_NotExportedToTheServer(t *testing.T) {
	// The server is started by the same script; a value resolved from X_FILE must
	// not be exported into the environment of child processes.
	script := secretResolutionBlock(t) + "\nenv | grep -c '^KEYORIX_ADMIN_PASSWORD=' || true\n"
	cmd := exec.Command("sh", "-c", "set -e\n"+script) //nolint:gosec // fixed shell, script from the repo
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "KEYORIX_ADMIN_PASSWORD_FILE=" + writeTmp(t, "pw\n")}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "0" {
		t.Errorf("KEYORIX_ADMIN_PASSWORD leaked into the environment of children: %q", out)
	}
}
