//go:build e2e

package journeys

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// runCLIInDir is runCLIExitCode with the CLI's working directory set, which is what a
// relative KEYORIX_TOKEN_FILE is resolved against.
func runCLIInDir(cliBin, dir string, env []string, args ...string) (stdout, stderr string, code int) {
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- the journey's own built binary and fixed arguments
	cmd.Dir = dir
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return so.String(), se.String(), ee.ExitCode()
	}
	if err != nil {
		return so.String(), se.String(), -1
	}
	return so.String(), se.String(), 0
}

// TestJourney_TokenFileRelativePath drives a RELATIVE KEYORIX_TOKEN_FILE against a real
// server (native SQLite), the leftover of SECRETENV-FIX-2 (#3564): a relative NAME_FILE may
// itself be the secret, so a refusal names the variable but never its value.
//
//	A. KEYORIX_TOKEN_FILE=./token, a 0600 file in the CLI's working directory, authenticates.
//	B. A relative path to a file that does not exist fails closed (exit 3) and the error does
//	   not contain the path value.
func TestJourney_TokenFileRelativePath(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	env := func(tokenFile string) []string {
		return []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + s.BaseURL, "KEYORIX_TOKEN_FILE=" + tokenFile}
	}

	t.Run("A: ./token in the working directory authenticates", func(t *testing.T) {
		wd := t.TempDir()
		if err := os.WriteFile(filepath.Join(wd, "token"), []byte(adminToken+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, errOut, code := runCLIInDir(cliBin, wd, env("./token"), "project", "list")
		if code != 0 {
			t.Fatalf("project list with KEYORIX_TOKEN_FILE=./token: exit %d\n%s%s", code, out, errOut)
		}

		// The same relative path from a directory without the file must not authenticate
		// (it is resolved against the working directory, nothing else).
		empty := t.TempDir()
		if _, _, code := runCLIInDir(cliBin, empty, env("./token"), "project", "list"); code == 0 {
			t.Fatal("KEYORIX_TOKEN_FILE=./token authenticated from a directory that has no such file")
		}
	})

	t.Run("B: a relative path to a missing file fails without echoing the path", func(t *testing.T) {
		const marker = "no-such-token-ZZQ7"
		wd := t.TempDir()
		out, errOut, code := runCLIInDir(cliBin, wd, env("./"+marker), "project", "list")
		if code != 3 {
			t.Fatalf("a missing token file must fail closed with exit 3, got %d\n%s%s", code, out, errOut)
		}
		if strings.Contains(out+errOut, marker) {
			t.Fatalf("the error echoes the relative path value:\n%s%s", out, errOut)
		}
		if !strings.Contains(errOut, "KEYORIX_TOKEN_FILE") {
			t.Errorf("the error should still name the variable so the user knows what to fix:\n%s", errOut)
		}
		if strings.Contains(out+errOut, adminToken) {
			t.Fatalf("the error contains the token:\n%s%s", out, errOut)
		}
	})
}
