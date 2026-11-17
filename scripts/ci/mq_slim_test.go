package ci_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	return runSelectWith(t, []string{"MQ_SLIM_MODE=" + mode}, files...)
}

// runSelectWith runs select-affected.py with extra environment entries (they
// win over the defaults below; MQ_SLIM_LEVERS is cleared so a developer's own
// value never leaks into a test).
func runSelectWith(t *testing.T, env []string, files ...string) (map[string]string, string) {
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
	cmd.Env = append(append(os.Environ(), "MQ_SLIM_LEVERS=", "GITHUB_EVENT_NAME=merge_group", "GITHUB_RUN_NUMBER=7"), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("select-affected.py (%v): %v\n%s", env, err, stderr.String())
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

// shadowRecords returns the MQ-SHADOW records of a select-affected log.
func shadowRecords(t *testing.T, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(log, "\n") {
		_, rec, ok := strings.Cut(line, "MQ-SHADOW ")
		if !ok {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(rec), &r); err != nil {
			t.Fatalf("MQ-SHADOW line is not JSON: %q", line)
		}
		out = append(out, r)
	}
	return out
}

// decisions is the sorted lever/check/decision list of a log: what each lever
// decided, without the per-run fields.
func decisions(t *testing.T, log string) []string {
	t.Helper()
	var out []string
	for _, r := range shadowRecords(t, log) {
		out = append(out, fmt.Sprintf("%v %v %v", r["lever"], r["check"], r["decision"]))
	}
	slices.Sort(out)
	return out
}

var gateKeys = []string{"gate_edge", "gate_e2e_smoke", "gate_smoke"}

// MQ_SLIM_MODE=enforce with MQ_SLIM_LEVERS=gate: the gate lever skips, the
// testreach lever is computed and logged but writes no leg_tests, and nothing
// else the script writes moves.
func TestMQSlim_GateOnlyEnforce(t *testing.T) {
	off, _ := runSelectEnv(t, "off", slimCase...)
	all, allLog := runSelectEnv(t, "enforce", slimCase...)
	gate, gateLog := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=gate"}, slimCase...)

	// Not vacuous: with every lever enforced the case does narrow legs.
	if all["leg_tests"] == "" || all["leg_tests"] == "{}" {
		t.Fatalf("fixture no longer exercises testreach: leg_tests=%q", all["leg_tests"])
	}
	if v, ok := gate["leg_tests"]; ok {
		t.Errorf("levers=gate wrote leg_tests=%q; testreach must stay shadow", v)
	}
	for _, k := range gateKeys {
		if v, ok := gate[k]; !ok || v != all[k] {
			t.Errorf("levers=gate: %s=%q (present=%v), enforce-all has %q", k, v, ok, all[k])
		}
	}
	for k, v := range off {
		if gate[k] != v {
			t.Errorf("levers=gate changed output %s: %q -> %q", k, v, gate[k])
		}
	}
	if len(gate) != len(off)+len(gateKeys) {
		t.Errorf("levers=gate writes %d outputs, want %d (off) + %d gate keys: %v", len(gate), len(off), len(gateKeys), keys(gate))
	}

	// Both levers keep deciding and logging; only the reported mode differs.
	if g, a := decisions(t, gateLog), decisions(t, allLog); !slices.Equal(g, a) {
		t.Errorf("levers=gate decisions differ from enforce-all:\n gate: %v\n all:  %v", g, a)
	}
	seen := map[string]int{}
	for _, r := range shadowRecords(t, gateLog) {
		lever, _ := r["lever"].(string)
		seen[lever]++
		want := "shadow"
		if lever == "gate" {
			want = "enforce"
		}
		if r["mode"] != want {
			t.Errorf("record of lever %s reports mode %v, want %s: %v", lever, r["mode"], want, r)
		}
	}
	if seen["testreach"] == 0 || seen["gate"] != 3 {
		t.Errorf("records per lever = %v, want testreach>0 and gate=3", seen)
	}
	if !strings.Contains(gateLog, "MQ-SLIM: enforcing gate;") {
		t.Errorf("no line saying which levers are enforced:\n%s", gateLog)
	}
}

// With MQ_SLIM_LEVERS unset, blank, or naming every lever, enforce is today's
// enforce: same outputs, same records, no new log line.
func TestMQSlim_LeversUnsetIsToday(t *testing.T) {
	base, baseLog := runSelectEnv(t, "enforce", slimCase...)
	for name, val := range map[string]string{
		"blank":           "  ",
		"both":            "gate,testreach",
		"case and spaces": " Gate , TESTREACH ",
		"with guards":     "gate,testreach,guards",
	} {
		t.Run(name, func(t *testing.T) {
			got, gotLog := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=" + val}, slimCase...)
			if !maps.Equal(got, base) {
				t.Errorf("outputs differ from levers unset:\n got:  %v\n base: %v", got, base)
			}
			if g, b := decisions(t, gotLog), decisions(t, baseLog); !slices.Equal(g, b) {
				t.Errorf("decisions differ from levers unset:\n got:  %v\n base: %v", g, b)
			}
			for _, r := range shadowRecords(t, gotLog) {
				if r["mode"] != "enforce" {
					t.Errorf("record mode %v, want enforce: %v", r["mode"], r)
				}
			}
		})
	}
	if strings.Contains(baseLog, "MQ-SLIM:") {
		t.Errorf("levers unset added a log line:\n%s", baseLog)
	}
	for _, r := range shadowRecords(t, baseLog) {
		if r["mode"] != "enforce" {
			t.Errorf("levers unset: record mode %v, want enforce: %v", r["mode"], r)
		}
	}
}

// A value that names no known lever enforces nothing (never "everything"):
// outputs equal shadow's and the unknown name is said out loud.
func TestMQSlim_UnknownLeversEnforceNothing(t *testing.T) {
	shadow, _ := runSelectEnv(t, "shadow", slimCase...)
	for name, val := range map[string]string{"typo": "gates", "comma only": ",", "guards only": "guards"} {
		t.Run(name, func(t *testing.T) {
			got, log := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=" + val}, slimCase...)
			if !maps.Equal(got, shadow) {
				t.Errorf("MQ_SLIM_LEVERS=%q wrote outputs beyond shadow's: %v", val, got)
			}
			if !strings.Contains(log, "MQ-SLIM: enforcing (no lever)") {
				t.Errorf("no 'enforcing (no lever)' line:\n%s", log)
			}
			if name == "typo" && !strings.Contains(log, "unknown lever(s) gates") {
				t.Errorf("typo not reported:\n%s", log)
			}
		})
	}
}

// The sampled full run (run number divisible by 10) opens everything whatever
// levers are enforced, and is off when no lever is enforced.
func TestMQSlim_SampledFullRun(t *testing.T) {
	for name, tc := range map[string]struct {
		levers   string
		wantMode string
	}{
		"unset":     {"", "full"},
		"gate only": {"gate", "full"},
		"testreach": {"testreach", "full"},
		"typo":      {"gates", "selected"},
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=" + tc.levers, "GITHUB_RUN_NUMBER=10"}, slimCase...)
			if got["mode"] != tc.wantMode {
				t.Fatalf("mode=%q, want %q", got["mode"], tc.wantMode)
			}
			if tc.wantMode == "full" {
				if got["legs"] != "{}" {
					t.Errorf("full run lists legs %q", got["legs"])
				}
				for _, k := range append(gateKeys, "leg_tests") {
					if _, ok := got[k]; ok {
						t.Errorf("full run wrote %s; ci.yml's defaults (run everything) must apply", k)
					}
				}
				for _, k := range []string{"gate_helm", "gate_web_e2e", "gate_fuzz_reach"} {
					if got[k] != "true" {
						t.Errorf("full run: %s=%q, want true", k, got[k])
					}
				}
			}
		})
	}
}

// MQ_SLIM_LEVERS parsing, called directly.
func TestMQSlim_LeverParsing(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const prog = "import sys, json; sys.path.insert(0, 'scripts/ci'); import mq_slim as m; print(json.dumps([sorted(m.enforced_levers()), m.unknown_levers()]))"
	for _, tc := range []struct {
		val     string
		enforce []string
		unknown []string
	}{
		{"", []string{"gate", "testreach"}, []string{}},
		{"   ", []string{"gate", "testreach"}, []string{}},
		{"gate", []string{"gate"}, []string{}},
		{"testreach", []string{"testreach"}, []string{}},
		{"gate,testreach", []string{"gate", "testreach"}, []string{}},
		{" GATE ,, Testreach ", []string{"gate", "testreach"}, []string{}},
		{"gate,guards", []string{"gate"}, []string{}},
		{"gate,bogus", []string{"gate"}, []string{"bogus"}},
		{"gates", []string{}, []string{"gates"}},
		{",", []string{}, []string{}},
		{"guards", []string{}, []string{}},
	} {
		cmd := exec.Command("python3", "-I", "-c", prog)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "MQ_SLIM_LEVERS="+tc.val)
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", tc.val, err)
		}
		var got [2][]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%q: %v: %s", tc.val, err, raw)
		}
		if !slices.Equal(got[0], tc.enforce) || !slices.Equal(got[1], tc.unknown) {
			t.Errorf("MQ_SLIM_LEVERS=%q: enforce=%v unknown=%v, want %v %v", tc.val, got[0], got[1], tc.enforce, tc.unknown)
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
	truncated := func(check string, runTests int, tests ...string) string {
		b, _ := json.Marshal(map[string]any{"v": 1, "lever": "testreach", "check": check, "decision": "would-narrow", "tests": tests,
			"run_tests": runTests, "tests_truncated": true, "why": "x", "mode": "shadow"})
		return "select-affected: MQ-SHADOW " + string(b)
	}
	for name, tc := range map[string]struct {
		records      []string
		jobs         []map[string]string
		misses       int
		inconclusive int
	}{
		"narrowed test fails inside the set": {
			[]string{rec("test-suite/http-1", "would-narrow", "TestNarrowedIn")},
			[]map[string]string{{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "failure", "log": failLog}}, 0, 0},
		"failing test outside the narrowed set": {
			[]string{rec("test-suite/http-1", "would-narrow", "TestNarrowedIn")},
			[]map[string]string{{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "failure", "log": outLog}}, 1, 0},
		"would-skip leg failed": {
			[]string{rec("test-suite/core-2", "would-skip")},
			[]map[string]string{{"name": "test-suite (core-2, 3300, coverage_core2.out)", "conclusion": "failure", "log": failLog}}, 1, 0},
		"would-skip gate job failed": {
			[]string{strings.Replace(rec("e2e-smoke", "would-skip"), `"testreach"`, `"gate"`, 1)},
			[]map[string]string{{"name": "e2e-smoke", "conclusion": "failure", "log": ""}}, 1, 0},
		"keep and passing legs are not misses": {
			[]string{rec("test-suite/http-2", "keep"), rec("test-suite/http-3", "would-skip")},
			[]map[string]string{
				{"name": "test-suite (http-2, 2400, coverage_http2.out)", "conclusion": "failure", "log": failLog},
				{"name": "test-suite (http-3, 2400, coverage_http3.out)", "conclusion": "success", "log": ""}}, 0, 0},
		// The merge_group matrix is fail-fast: the first failing leg cancels
		// the others, so a narrowed leg that would also have failed ends
		// cancelled. That is no evidence either way (REVIEW-4196-DEEP-1 M2).
		"would-skip leg cancelled by fail-fast": {
			[]string{rec("test-suite/http-1", "keep"), rec("test-suite/core-2", "would-skip")},
			[]map[string]string{
				{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "failure", "log": failLog},
				{"name": "test-suite (core-2, 3300, coverage_core2.out)", "conclusion": "cancelled", "log": ""}}, 0, 1},
		"would-narrow leg timed out": {
			[]string{rec("test-suite/http-1", "would-narrow", "TestNarrowedIn")},
			[]map[string]string{{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "timed_out", "log": ""}}, 0, 1},
		"would-skip leg missing from the run": {
			[]string{rec("test-suite/core-2", "would-skip")}, []map[string]string{}, 0, 1},
		"would-skip gate job cancelled": {
			[]string{strings.Replace(rec("smoke", "would-skip"), `"testreach"`, `"gate"`, 1)},
			[]map[string]string{{"name": "smoke", "conclusion": "cancelled", "log": ""}}, 0, 1},
		"failed test beyond a truncated logged list": {
			[]string{truncated("test-suite/http-1", 41, "TestNarrowedIn")},
			[]map[string]string{{"name": "test-suite (http-1, 2400, coverage_http1.out)", "conclusion": "failure", "log": outLog}}, 0, 1},
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
			if got := strings.Count(string(out), "MISS "); got != tc.misses {
				t.Fatalf("misses=%d, want %d\n%s", got, tc.misses, out)
			}
			if got := strings.Count(string(out), "INCONCLUSIVE "); got != tc.inconclusive {
				t.Fatalf("inconclusive=%d, want %d\n%s", got, tc.inconclusive, out)
			}
			// 1 with misses, 3 with only inconclusive checks, 0 when clean.
			want := 0
			if tc.misses > 0 {
				want = 1
			} else if tc.inconclusive > 0 {
				want = 3
			}
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != want {
				t.Fatalf("exit %d, want %d\n%s", code, want, out)
			}
		})
	}
}
