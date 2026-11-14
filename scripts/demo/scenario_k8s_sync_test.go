package demo_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// k8sSyncEnv returns an environment where kubectl, kind and docker exist (stubs that
// succeed), so scenario-k8s-sync.sh gets past its prerequisite check to its input
// check, and none of its three inputs is set.
func k8sSyncEnv(t *testing.T) []string {
	t.Helper()
	bin := t.TempDir()
	for _, tool := range []string{"kubectl", "kind", "docker"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KEYORIX_") || strings.HasPrefix(kv, "KX_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func runScript(t *testing.T, env []string, name string, args ...string) (code int, out string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{name}, args...)...)
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatal(err)
	}
	return code, string(b)
}

// TestScenarioK8sSync_MissingInputsIsSkippedNotFailed: with its prerequisites present
// but KEYORIX_SERVER / KEYORIX_TOKEN / KX_SECRET_ID unset, the scenario exits 2
// (SKIPPED, as the other scenarios do), naming all three variables, instead of dying
// with exit 1 and `KEYORIX_SERVER: set KEYORIX_SERVER`.
func TestScenarioK8sSync_MissingInputsIsSkippedNotFailed(t *testing.T) {
	code, out := runScript(t, k8sSyncEnv(t), "scenario-k8s-sync.sh")
	if code != 2 {
		t.Fatalf("want exit 2 (SKIPPED), got %d:\n%s", code, out)
	}
	for _, v := range []string{"KEYORIX_SERVER", "KEYORIX_TOKEN", "KX_SECRET_ID"} {
		if !strings.Contains(out, v) {
			t.Errorf("message must name %s:\n%s", v, out)
		}
	}
	if strings.Contains(out, "KEYORIX_SERVER: set KEYORIX_SERVER") {
		t.Errorf("the bash ':?' abort text is back:\n%s", out)
	}
}

// TestCatalogueCheck_ReportsK8sSyncWithoutInputsAsSkipped: the catalogue's exit-code
// table turns the scenario's exit 2 into SKIPPED, and a SKIPPED scenario is not a failure.
func TestCatalogueCheck_ReportsK8sSyncWithoutInputsAsSkipped(t *testing.T) {
	env := append(k8sSyncEnv(t), "KEYORIX_DEMO_DIR="+t.TempDir())
	code, out := runScript(t, env, "catalogue-check.sh", "k8s-sync")
	if code != 0 {
		t.Fatalf("a SKIPPED scenario must not fail the catalogue, got exit %d:\n%s", code, out)
	}
	if !regexp.MustCompile(`(?m)^k8s-sync\s+SKIPPED\s`).MatchString(out) {
		t.Fatalf("want a 'k8s-sync SKIPPED' line:\n%s", out)
	}
}
