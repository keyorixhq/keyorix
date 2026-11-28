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
	"sync"
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
//
// Every run is a full `go list ./...` plus a lex of every Go file of the
// module, and the script is deterministic for one (env, files) pair against
// the checkout the tests read, so identical invocations are run once per test
// binary and share the result (the callers get their own copy of the map).
// Runs with different env or files are never merged: each assertion still
// compares real runs of the unchanged script.
func runSelectWith(t *testing.T, env []string, files ...string) (map[string]string, string) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	key := strings.Join(env, "\x00") + "\x01" + strings.Join(files, "\x00")
	slimRunsMu.Lock()
	r := slimRuns[key]
	if r == nil {
		r = &slimRun{}
		slimRuns[key] = r
	}
	slimRunsMu.Unlock()
	r.once.Do(func() { r.kv, r.log, r.err = execSelect(env, files) })
	if r.err != nil {
		t.Fatal(r.err)
	}
	return maps.Clone(r.kv), r.log
}

type slimRun struct {
	once sync.Once
	kv   map[string]string
	log  string
	err  error
}

var (
	slimRunsMu sync.Mutex
	slimRuns   = map[string]*slimRun{}
)

func execSelect(env []string, files []string) (map[string]string, string, error) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return nil, "", err
	}
	dir, err := os.MkdirTemp("", "mqslim")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "github_output")
	args := append([]string{"scripts/ci/select-affected.py", "--github-output", out, "--changed"}, files...)
	cmd := exec.Command("python3", args...)
	cmd.Dir = root
	cmd.Env = append(append(os.Environ(), "MQ_SLIM_LEVERS=", "MQ_SLIM_TESTREACH_CHECKS=", "GITHUB_EVENT_NAME=merge_group", "GITHUB_RUN_NUMBER=7"), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("select-affected.py (%v): %w\n%s", env, err, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, "", err
	}
	kv := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		kv[k] = v
	}
	return kv, stderr.String(), nil
}

// A web/ change plus a changelog fragment: rule 3 selects many legs through
// one-word literals ("web", "changelog.d"), the case testreach narrows.
var slimCase = []string{
	filepath.Join("web", "e2e", "real", "demo-permission-aware.spec.ts"),
	filepath.Join("changelog.d", "zz-mq-test-slim-1-fixture.md"),
}

func TestMQSlim_ShadowNeverChangesTheOutputs(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	base, baseLog := runSelectEnv(t, "enforce", slimCase...)
	for name, val := range map[string]string{
		"blank":           "  ",
		"both":            "gate,testreach",
		"case and spaces": " Gate , TESTREACH ",
		"with guards":     "gate,testreach,guards",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
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
	t.Parallel()
	shadow, _ := runSelectEnv(t, "shadow", slimCase...)
	for name, val := range map[string]string{"typo": "gates", "comma only": ",", "guards only": "guards"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
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
	t.Parallel()
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
			t.Parallel()
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

// recordFor returns the record of one check of one lever.
func recordFor(t *testing.T, log, lever, check string) map[string]any {
	t.Helper()
	for _, r := range shadowRecords(t, log) {
		if r["lever"] == lever && r["check"] == check {
			return r
		}
	}
	t.Fatalf("no %s record for %s in:\n%s", lever, check, log)
	return nil
}

// MQ_SLIM_TESTREACH_CHECKS: with testreach enforced, only the listed checks
// get a leg_tests entry. slimCase narrows exactly one check, test-suite/root-1
// (server/webui); the other selected legs are kept whole.
func TestMQSlim_TestreachCheckList(t *testing.T) {
	t.Parallel()
	const narrowed = "test-suite/root-1"
	shadow, _ := runSelectEnv(t, "shadow", slimCase...)
	base, baseLog := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=testreach"}, slimCase...)
	if base["leg_tests"] == "" || base["leg_tests"] == "{}" || recordFor(t, baseLog, "testreach", narrowed)["decision"] != "would-narrow" {
		t.Fatalf("fixture no longer narrows %s: leg_tests=%q", narrowed, base["leg_tests"])
	}

	t.Run("listed check enforces as before", func(t *testing.T) {
		t.Parallel()
		for _, val := range []string{" test-suite/root-2 , test-suite/root-1, ", "test-suite/root-1,test-suite/nope"} {
			got, log := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=testreach", "MQ_SLIM_TESTREACH_CHECKS=" + val}, slimCase...)
			if !maps.Equal(got, base) {
				t.Errorf("list %q: outputs differ from the unlisted run:\n got:  %v\n base: %v", val, got, base)
			}
			if r := recordFor(t, log, "testreach", narrowed); r["mode"] != "enforce" {
				t.Errorf("list %q: %s mode %v, want enforce", val, narrowed, r["mode"])
			}
		}
	})

	t.Run("unlisted check is computed and logged but not enforced", func(t *testing.T) {
		t.Parallel()
		// A valid name no decision uses (typo, or another check) is harmless.
		for _, val := range []string{"test-suite/root-2", "TEST-SUITE/ROOT-1"} {
			got, log := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=testreach", "MQ_SLIM_TESTREACH_CHECKS=" + val}, slimCase...)
			if got["leg_tests"] != "{}" {
				t.Errorf("list %q: leg_tests=%q, want {} (root-1 must run unchanged)", val, got["leg_tests"])
			}
			delete(got, "leg_tests")
			if !maps.Equal(got, shadow) {
				t.Errorf("list %q: outputs beyond shadow's: %v", val, got)
			}
			r := recordFor(t, log, "testreach", narrowed)
			if r["decision"] != "would-narrow" || r["mode"] != "shadow" {
				t.Errorf("list %q: %s decision=%v mode=%v, want would-narrow shadow", val, narrowed, r["decision"], r["mode"])
			}
			if g, b := decisions(t, log), decisions(t, baseLog); !slices.Equal(g, b) {
				t.Errorf("list %q: decisions changed:\n got:  %v\n base: %v", val, g, b)
			}
			if !strings.Contains(log, "MQ-SLIM: testreach enforced only for") {
				t.Errorf("list %q: no line saying which checks are enforced:\n%s", val, log)
			}
		}
	})

	t.Run("unset or blank is every check", func(t *testing.T) {
		t.Parallel()
		for _, val := range []string{"   "} {
			got, log := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=testreach", "MQ_SLIM_TESTREACH_CHECKS=" + val}, slimCase...)
			if !maps.Equal(got, base) {
				t.Errorf("list %q: outputs differ from unset", val)
			}
			if strings.Contains(log, "MQ-SLIM: testreach enforced only") {
				t.Errorf("list %q: blank list reported as a restriction:\n%s", val, log)
			}
		}
	})

	t.Run("unparseable list enforces nothing for testreach", func(t *testing.T) {
		t.Parallel()
		for _, val := range []string{"test-suite/root-1;test-suite/root-2", " , ,"} {
			got, log := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=testreach", "MQ_SLIM_TESTREACH_CHECKS=" + val}, slimCase...)
			if !maps.Equal(got, shadow) {
				t.Errorf("list %q wrote outputs beyond shadow's: %v", val, got)
			}
			var errs int
			for _, r := range shadowRecords(t, log) {
				if r["mode"] != "shadow" {
					t.Errorf("list %q: record not shadow: %v", val, r)
				}
				if r["decision"] == "error" && r["lever"] == "testreach" {
					errs++
				}
			}
			if errs != 1 {
				t.Errorf("list %q: %d testreach error records, want 1:\n%s", val, errs, log)
			}
			if r := recordFor(t, log, "testreach", narrowed); r["decision"] != "would-narrow" {
				t.Errorf("list %q: decision no longer computed: %v", val, r)
			}
		}
	})

	t.Run("gate and guards are unaffected", func(t *testing.T) {
		all, _ := runSelectEnv(t, "enforce", slimCase...)
		for _, list := range []string{"test-suite/root 1"} {
			got, log := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=gate,testreach,guards", "MQ_SLIM_TESTREACH_CHECKS=" + list}, slimCase...)
			for _, k := range gateKeys {
				if got[k] != all[k] || got[k] == "" {
					t.Errorf("list %q: %s=%q, want %q", list, k, got[k], all[k])
				}
			}
			if strings.Contains(log, "unknown lever") {
				t.Errorf("list %q: levers misread:\n%s", list, log)
			}
			for _, r := range shadowRecords(t, log) {
				if r["lever"] == "gate" && r["mode"] != "enforce" {
					t.Errorf("list %q: gate record mode %v, want enforce: %v", list, r["mode"], r)
				}
			}
		}
		// MQ_SLIM_LEVERS=gate: the list is irrelevant, testreach stays shadow.
		got, _ := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=gate", "MQ_SLIM_TESTREACH_CHECKS=" + narrowed}, slimCase...)
		if v, ok := got["leg_tests"]; ok {
			t.Errorf("levers=gate with a list wrote leg_tests=%q", v)
		}
	})

	t.Run("sampled full run still happens", func(t *testing.T) {
		for _, tc := range []struct{ list, want string }{
			{"test-suite/root-1", "full"},
			{"test-suite/root-2", "full"},
			{"test-suite/root 1", "selected"}, // unparseable: nothing enforced, nothing to net
		} {
			got, _ := runSelectWith(t, []string{"MQ_SLIM_MODE=enforce", "MQ_SLIM_LEVERS=testreach", "MQ_SLIM_TESTREACH_CHECKS=" + tc.list, "GITHUB_RUN_NUMBER=10"}, slimCase...)
			if got["mode"] != tc.want {
				t.Errorf("list %q: mode=%q, want %q", tc.list, got["mode"], tc.want)
			}
			if tc.want == "full" {
				if _, ok := got["leg_tests"]; ok {
					t.Errorf("list %q: full run wrote leg_tests", tc.list)
				}
			}
		}
	})
}

// MQ_SLIM_TESTREACH_CHECKS parsing, called directly.
func TestMQSlim_TestreachCheckParsing(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const prog = "import sys, json; sys.path.insert(0, 'scripts/ci'); import mq_slim as m; n, e = m.testreach_checks(); print(json.dumps([None if n is None else sorted(n), bool(e), [m.testreach_allows(c) for c in ('test-suite/root-1', 'test-suite/root-2', 'test-suite/root-4')]]))"
	for _, tc := range []struct {
		val   string
		names []string // nil: no list
		bad   bool
		allow [3]bool
	}{
		{"", nil, false, [3]bool{true, true, true}},
		{"   ", nil, false, [3]bool{true, true, true}},
		{"test-suite/root-1", []string{"test-suite/root-1"}, false, [3]bool{true, false, false}},
		{"test-suite/root-1,test-suite/root-2", []string{"test-suite/root-1", "test-suite/root-2"}, false, [3]bool{true, true, false}},
		{" test-suite/root-2 ,, test-suite/root-2,", []string{"test-suite/root-2"}, false, [3]bool{false, true, false}},
		{"test-suite/root-9", []string{"test-suite/root-9"}, false, [3]bool{false, false, false}},
		{"test-suite/Root-1", []string{"test-suite/Root-1"}, false, [3]bool{false, false, false}},
		{"test-suite/root 1", []string{}, true, [3]bool{false, false, false}},
		{"test-suite/root-1,*", []string{}, true, [3]bool{false, false, false}},
		{",", []string{}, true, [3]bool{false, false, false}},
		// REVIEW-4693-DEEP-1 M1: a sharded leg in the list (alone, or beside an
		// unsharded one) is refused whole; red on a020259f, which allowed it and
		// let "http-2": "-" skip tests that http-1's weight partition never runs.
		{"test-suite/http-2", []string{}, true, [3]bool{false, false, false}},
		{"test-suite/root-1,test-suite/server-3", []string{}, true, [3]bool{false, false, false}},
		{"test-suite/storage-store-1", []string{}, true, [3]bool{false, false, false}},
		{"test-suite/handlers-2,test-suite/root-2", []string{}, true, [3]bool{false, false, false}},
		// not a shard name: stays allowed
		{"test-suite/http-x,test-suite/root-1", []string{"test-suite/http-x", "test-suite/root-1"}, false, [3]bool{true, false, false}},
	} {
		cmd := exec.Command("python3", "-I", "-c", prog)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "MQ_SLIM_TESTREACH_CHECKS="+tc.val)
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", tc.val, err)
		}
		var got struct {
			Names []string
			Bad   bool
			Allow [3]bool
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil || len(arr) != 3 {
			t.Fatalf("%q: %v: %s", tc.val, err, raw)
		}
		_ = json.Unmarshal(arr[0], &got.Names)
		_ = json.Unmarshal(arr[1], &got.Bad)
		_ = json.Unmarshal(arr[2], &got.Allow)
		if !slices.Equal(got.Names, tc.names) || got.Bad != tc.bad || got.Allow != tc.allow {
			t.Errorf("MQ_SLIM_TESTREACH_CHECKS=%q: names=%v bad=%v allow=%v, want %v %v %v", tc.val, got.Names, got.Bad, got.Allow, tc.names, tc.bad, tc.allow)
		}
	}
}

// mq_slim.SHARDED_LEG must stay the same pattern as select-affected.py's
// SHARDED_SINGLE_PACKAGE, or a new sharded package could be listed again.
func TestMQSlim_ShardedLegPatternMatchesSelectAffected(t *testing.T) {
	pat := func(file, name string) string {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for l := range strings.SplitSeq(string(b), "\n") {
			if rest, ok := strings.CutPrefix(l, name+" = re.compile("); ok {
				return strings.TrimSpace(rest)
			}
		}
		t.Fatalf("%s: no %s", file, name)
		return ""
	}
	if a, b := pat("mq_slim.py", "SHARDED_LEG"), pat("select-affected.py", "SHARDED_SINGLE_PACKAGE"); a != b {
		t.Errorf("SHARDED_LEG %s differs from SHARDED_SINGLE_PACKAGE %s", a, b)
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
			t.Parallel()
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
