package main

// boot_exit_codes_integration_test.go -- EDGE-STARTUP-NOV-1: a server that
// cannot start must say WHY with its exit status, so a service manager can stop
// retrying what only an operator can fix (docs/edge-deployment.md §7a).
//
// Drives the real built binary, the way the shipped systemd unit starts it:
//   - missing passphrase file, missing key file, unparseable config -> 78
//     (exitOperatorFix: restarting cannot help);
//   - an aws-kms provider whose endpoint refuses connections -> 75
//     (exitDependencyDown: the KMS may come back);
// and each leaves ONE hint line last on stderr that names neither a secret nor
// a path. The numbers are literals here on purpose: TestExitCodes_* in
// boot_exit_test.go ties them to the constants and to the systemd unit.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bootAttempt runs the server once with the given arguments and environment and
// returns its exit status and stderr.
func bootAttempt(t *testing.T, e *edgeInstall, env []string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.bin, args...) //nolint:gosec // this suite's own binary
	cmd.Dir = e.dir
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("the server neither started nor exited within 90s:\n%s", stderr.String())
	}
	if err == nil {
		t.Fatalf("the server exited 0 where a boot failure was expected:\n%s", stderr.String())
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("running the server: %v", err)
	}
	return ee.ExitCode(), stderr.String()
}

// bootEnv is the install's environment without the master passphrase, as the
// unit gives it (the passphrase only comes from a credential file).
func bootEnv(e *edgeInstall, extra ...string) []string {
	var env []string
	for _, kv := range e.env {
		if !strings.HasPrefix(kv, "KEYORIX_MASTER_PASSWORD=") {
			env = append(env, kv)
		}
	}
	return append(append(env, "KEYORIX_CONFIG_PATH=./keyorix.yaml"), extra...)
}

// lastLine is the last non-empty line of s.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func requireHint(t *testing.T, e *edgeInstall, stderr, wantPrefix string) {
	t.Helper()
	hint := lastLine(stderr)
	if !strings.HasPrefix(hint, wantPrefix) {
		t.Errorf("last stderr line = %q, want it to start with %q\nfull stderr:\n%s", hint, wantPrefix, stderr)
	}
	// One line, no secrets, no paths beyond what the log lines above already carry.
	for _, banned := range []string{e.dir, "edge-unattended-test-passphrase", "keys/", ".key", ".salt"} {
		if strings.Contains(hint, banned) {
			t.Errorf("operator hint %q contains %q", hint, banned)
		}
	}
}

func TestBootExitCodes_OperatorFixIs78(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	bin := buildServerBinary(t)

	cases := []struct {
		name   string
		break_ func(t *testing.T, e *edgeInstall)
		args   []string
	}{
		{
			name:   "missing passphrase file",
			break_: func(*testing.T, *edgeInstall) {},
			args:   []string{"--passphrase-file=./does-not-exist"},
		},
		{
			name: "missing key file",
			break_: func(t *testing.T, e *edgeInstall) {
				if err := os.Remove(filepath.Join(e.dir, "keys", "dek.key")); err != nil {
					t.Fatal(err)
				}
			},
			args: []string{"--passphrase-file=./pass"},
		},
		{
			name: "unparseable configuration",
			break_: func(t *testing.T, e *edgeInstall) {
				if err := os.WriteFile(filepath.Join(e.dir, "keyorix.yaml"), []byte("server: [this is: not valid\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			args: []string{"--passphrase-file=./pass"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEdgeInstall(t, bin, true)
			if err := os.WriteFile(filepath.Join(e.dir, "pass"), []byte("edge-unattended-test-passphrase\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.break_(t, e)
			code, stderr := bootAttempt(t, e, bootEnv(e), tc.args...)
			if code != 78 {
				t.Errorf("exit status = %d, want 78 (operator must fix)\nstderr:\n%s", code, stderr)
			}
			requireHint(t, e, stderr, "keyorix-server: exit 78 ")
		})
	}
}

func TestBootExitCodes_UnreachableKMSIs75(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	bin := buildServerBinary(t)
	e := newEdgeInstall(t, bin, true)

	cfgPath := filepath.Join(e.dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	const saltLine = "    salt_path: \"keys/kek.salt\"\n"
	if !strings.Contains(string(raw), saltLine) {
		t.Fatal("config template no longer has the salt_path line this test extends")
	}
	kms := saltLine + "    key_provider:\n      type: aws-kms\n      kms_key_id: alias/edge-test\n      wrapped_key_path: keys/kek.wrapped\n"
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(string(raw), saltLine, kms, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "keys", "kek.wrapped"), []byte("not a real wrapped key"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The stub: an address nothing listens on, so every KMS call is refused.
	env := bootEnv(e,
		"AWS_ENDPOINT_URL=http://127.0.0.1:"+freeTCPPort(t),
		"AWS_REGION=us-east-1",
		"AWS_ACCESS_KEY_ID=AKIAEDGETEST",
		"AWS_SECRET_ACCESS_KEY=edge-test-secret",
		"AWS_EC2_METADATA_DISABLED=true",
	)
	code, stderr := bootAttempt(t, e, env)
	if code != 75 {
		t.Errorf("exit status = %d, want 75 (a dependency that may come back)\nstderr:\n%s", code, stderr)
	}
	requireHint(t, e, stderr, "keyorix-server: exit 75 ")
}
