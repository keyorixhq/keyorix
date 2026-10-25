package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests run scripts/ci/retry-net.sh against a fake command that prints a
// fixture on stderr and fails a given number of times. The fixtures in
// testdata/retry-net are real error lines from failed merge-queue jobs (see
// testdata/retry-net/README.md for the run and job of each), plus the real
// output of `go mod download` against a tampered go.sum.

const fakeNetCmd = `#!/usr/bin/env bash
n=$(cat "$COUNT_FILE" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$COUNT_FILE"
echo "stdout-$n"
if [ "$n" -le "$FAIL_TIMES" ]; then
  cat "$FIXTURE" >&2
  exit 7
fi
exit 0
`

type netRun struct {
	stdout, stderr string
	code, calls    int
}

func runRetryNet(t *testing.T, fixture string, failTimes int, extraEnv ...string) netRun {
	t.Helper()
	dir := t.TempDir()
	cmdPath := filepath.Join(dir, "fake-cmd")
	if err := os.WriteFile(cmdPath, []byte(fakeNetCmd), 0o700); err != nil { //nolint:gosec // test-only fake, must be executable
		t.Fatal(err)
	}
	fx, err := filepath.Abs(filepath.Join("testdata", "retry-net", fixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fx); err != nil {
		t.Fatal(err)
	}
	count := filepath.Join(dir, "count")
	cmd := exec.Command("bash", "retry-net.sh", cmdPath) //nolint:gosec // this repo's own script
	cmd.Env = append(os.Environ(),
		"COUNT_FILE="+count, "FIXTURE="+fx, "FAIL_TIMES="+strconv.Itoa(failTimes),
		"RETRY_NET_DELAYS=0 0", "RETRY_NET_ATTEMPTS=")
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	calls := 0
	if raw, err := os.ReadFile(count); err == nil { //nolint:gosec // path from t.TempDir
		calls, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
	}
	return netRun{stdout.String(), stderr.String(), code, calls}
}

func TestRetryNet_RetriesRealNetworkFailures(t *testing.T) {
	for _, fx := range []string{
		"proxy-tls-timeout.txt",      // licenses, 3 Oct
		"proxy-stream-error.txt",     // licenses, 20 Oct
		"dockerhub-500.txt",          // demo-up-smoke / helm-boot-smoke, 23 Oct
		"dockerhub-unauthorized.txt", // docker-boot-smoke (buildkit pull), 23 Oct
	} {
		t.Run(fx, func(t *testing.T) {
			r := runRetryNet(t, fx, 1)
			if r.code != 0 || r.calls != 2 {
				t.Fatalf("one network failure then success: want exit 0 after 2 calls, got exit %d after %d\n%s", r.code, r.calls, r.stderr)
			}
			if !strings.Contains(r.stderr, "::warning::retry-net: attempt 1/3") {
				t.Errorf("a retry must be announced with a ::warning:: annotation, stderr:\n%s", r.stderr)
			}
			if r.stdout != "stdout-1\nstdout-2\n" {
				t.Errorf("stdout must pass through unchanged, got %q", r.stdout)
			}
		})
	}
}

func TestRetryNet_GivesUpAfterThreeAttempts(t *testing.T) {
	r := runRetryNet(t, "proxy-stream-error.txt", 99)
	if r.code != 7 || r.calls != 3 {
		t.Fatalf("persistent network failure: want the command's exit 7 after 3 calls, got exit %d after %d", r.code, r.calls)
	}
	if !strings.Contains(r.stderr, "giving up") {
		t.Errorf("the final failure must say it gave up, stderr:\n%s", r.stderr)
	}
}

func TestRetryNet_AttemptsCannotExceedThree(t *testing.T) {
	r := runRetryNet(t, "dockerhub-500.txt", 99, "RETRY_NET_ATTEMPTS=9")
	if r.calls != 3 {
		t.Fatalf("RETRY_NET_ATTEMPTS=9 must be capped at 3 attempts, got %d", r.calls)
	}
	r = runRetryNet(t, "dockerhub-500.txt", 99, "RETRY_NET_ATTEMPTS=1")
	if r.calls != 1 || r.code != 7 {
		t.Fatalf("RETRY_NET_ATTEMPTS=1 must run once and keep exit 7, got %d calls, exit %d", r.calls, r.code)
	}
}

func TestRetryNet_NeverRetriesOtherFailures(t *testing.T) {
	for _, fx := range []string{
		"compile-error.txt",               // preflight/lint, 5 Oct (class C)
		"init-secrets-refusal.txt",        // docker-boot-smoke, 21 Oct (queue parity)
		"localhost-refused.txt",           // helm-boot-smoke dump step: a local server, not the network
		"gosum-mismatch.txt",              // real `go mod download` against a tampered go.sum
		"gosum-mismatch-plus-network.txt", // integrity wins even next to a network line
	} {
		t.Run(fx, func(t *testing.T) {
			r := runRetryNet(t, fx, 1)
			if r.code != 7 || r.calls != 1 {
				t.Fatalf("not a transient network error: want exit 7 after 1 call, got exit %d after %d\n%s", r.code, r.calls, r.stderr)
			}
			if strings.Contains(r.stderr, "::warning::") {
				t.Errorf("no retry may be announced, stderr:\n%s", r.stderr)
			}
		})
	}
}

func TestRetryNet_SuccessRunsOnce(t *testing.T) {
	r := runRetryNet(t, "proxy-tls-timeout.txt", 0)
	if r.code != 0 || r.calls != 1 || r.stderr != "" {
		t.Fatalf("a passing command must run once, silently: exit %d, %d calls, stderr %q", r.code, r.calls, r.stderr)
	}
}
