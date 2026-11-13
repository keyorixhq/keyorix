package ci_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These pin scripts/ci/mq_slim.py (MQ-TEST-SLIM-1) and its evidence script.
// The load-bearing property is the first one: in shadow mode (the default,
// and what every merge_group run gets until ci.yml passes the repository
// variable) select-affected.py's outputs are byte-identical to mode off, so
// the levers can only log, never skip.

func runSelectEnv(t *testing.T, mode string, files ...string) (map[string]string, string) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "github_output")
	args := append([]string{"scripts/ci/select-affected.py", "--github-output", out, "--changed"}, files...)
	cmd := exec.Command("python3", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "MQ_SLIM_MODE="+mode, "GITHUB_EVENT_NAME=merge_group", "GITHUB_RUN_NUMBER=7")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("select-affected.py (%s): %v\n%s", mode, err, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	kv := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		kv[k] = v
	}
	return kv, stderr.String()
}

// A web/ change plus a changelog fragment: rule 3 selects many legs through
// one-word literals ("web", "changelog.d"), the case testreach narrows.
var slimCase = []string{
	filepath.Join("web", "e2e", "real", "demo-permission-aware.spec.ts"),
	filepath.Join("changelog.d", "zz-mq-test-slim-1-fixture.md"),
}

func TestMQSlim_ShadowNeverChangesTheOutputs(t *testing.T) {
	off, offLog := runSelectEnv(t, "off", slimCase...)
	shadow, shadowLog := runSelectEnv(t, "shadow", slimCase...)
	if strings.Contains(offLog, "MQ-SHADOW ") {
		t.Errorf("mode off logged shadow records:\n%s", offLog)
	}
	if !strings.Contains(shadowLog, "MQ-SHADOW ") {
		t.Fatalf("mode shadow logged no MQ-SHADOW record:\n%s", shadowLog)
	}
	if len(off) != len(shadow) {
		t.Errorf("output keys differ: off=%d shadow=%d", len(off), len(shadow))
	}
	for k, v := range off {
		if shadow[k] != v {
			t.Errorf("output %s: off=%q shadow=%q", k, v, shadow[k])
		}
	}
	for line := range strings.SplitSeq(shadowLog, "\n") {
		_, rec, ok := strings.Cut(line, "MQ-SHADOW ")
		if !ok {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(rec), &r); err != nil {
			t.Errorf("MQ-SHADOW line is not JSON: %q", line)
			continue
		}
		for _, f := range []string{"v", "lever", "check", "decision", "why", "mode"} {
			if _, ok := r[f]; !ok {
				t.Errorf("MQ-SHADOW record without %q: %s", f, rec)
			}
		}
		if r["decision"] == "error" {
			t.Errorf("shadow lever failed: %s", rec)
		}
	}
}

// enforce only ADDS outputs; everything off/shadow writes stays identical.
func TestMQSlim_EnforceAddsOutputsOnly(t *testing.T) {
	off, _ := runSelectEnv(t, "off", slimCase...)
	enf, _ := runSelectEnv(t, "enforce", slimCase...)
	for k, v := range off {
		if enf[k] != v {
			t.Errorf("enforce changed output %s: %q -> %q", k, v, enf[k])
		}
	}
	for _, k := range []string{"leg_tests", "gate_edge", "gate_e2e_smoke", "gate_smoke"} {
		if _, ok := enf[k]; !ok {
			t.Errorf("enforce: no %s output (got keys %v)", k, keys(enf))
		}
	}
	var legTests map[string]string
	if err := json.Unmarshal([]byte(enf["leg_tests"]), &legTests); err != nil {
		t.Fatalf("leg_tests is not JSON: %q", enf["leg_tests"])
	}
	for leg, rx := range legTests {
		if rx != "-" && !(strings.HasPrefix(rx, "^(") && strings.HasSuffix(rx, ")$")) {
			t.Errorf("leg_tests[%s]=%q, want \"-\" or ^(...)$", leg, rx)
		}
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// mq-shadow-report.py: what counts as a miss.
func TestMQShadowReport_Misses(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	rec := func(check, decision string, tests ...string) string {
		b, _ := json.Marshal(map[string]any{"v": 1, "lever": "testreach", "check": check, "decision": decision, "tests": tests, "why": "x", "mode": "shadow"})
		return "2026-11-14T10:00:00.0Z select-affected: MQ-SHADOW " + string(b)
	}
	failLog := "=== RUN   TestNarrowedIn\n--- FAIL: TestNarrowedIn (0.01s)\n    x_test.go:1: boom\nFAIL\n"
	outLog := "--- FAIL: TestOutside/sub (0.00s)\n"
	for name, tc := range map[string]struct {
		records []string
		jobs    []map[string]string
		misses  int
	}{
		"narrowed test fails inside the set": {
			[]string{rec("test-suite/http-1", "would-narrow", "TestNarrowedIn")},
			[]map[string]string{{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "failure", "log": failLog}}, 0},
		"failing test outside the narrowed set": {
			[]string{rec("test-suite/http-1", "would-narrow", "TestNarrowedIn")},
			[]map[string]string{{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "failure", "log": outLog}}, 1},
		"would-skip leg failed": {
			[]string{rec("test-suite/core-2", "would-skip")},
			[]map[string]string{{"name": "test-suite (core-2, 3300, coverage_core2.out)", "conclusion": "failure", "log": failLog}}, 1},
		"would-skip gate job failed": {
			[]string{strings.Replace(rec("e2e-smoke", "would-skip"), `"testreach"`, `"gate"`, 1)},
			[]map[string]string{{"name": "e2e-smoke", "conclusion": "failure", "log": ""}}, 1},
		"keep and passing legs are not misses": {
			[]string{rec("test-suite/http-2", "keep"), rec("test-suite/http-3", "would-skip")},
			[]map[string]string{
				{"name": "test-suite (http-2, 2400, coverage_http2.out)", "conclusion": "failure", "log": failLog},
				{"name": "test-suite (http-3, 2400, coverage_http3.out)", "conclusion": "success", "log": ""}}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "4242")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "select.log"), []byte(strings.Join(tc.records, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			jb, _ := json.Marshal(tc.jobs)
			if err := os.WriteFile(filepath.Join(dir, "jobs.json"), jb, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("python3", "mq-shadow-report.py", "--logs-dir", filepath.Dir(dir))
			out, err := cmd.CombinedOutput()
			got := strings.Count(string(out), "MISS ")
			if got != tc.misses {
				t.Fatalf("misses=%d, want %d\n%s", got, tc.misses, out)
			}
			if (err != nil) != (tc.misses > 0) {
				t.Fatalf("exit error=%v with %d misses, want non-zero exactly when there are misses\n%s", err, tc.misses, out)
			}
		})
	}
}
