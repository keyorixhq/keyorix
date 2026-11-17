package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests run scripts/ci/rerun-known-flakes.py against a fake `go` on PATH.
// The "first run" outputs in testdata/rerun are copied from the real failed
// logs of the merge queue (repo-guards run 43664286604 TestGovulncheckCheckScript,
// 43654205075 TestEdgeUnattended_InterruptedMigrationCompletes, root-4 run
// 43726111215 the P9 case, core-1 run 43591322921 the PG canary), with only the
// job/step/timestamp prefix of each line removed. The fake go prints one of them
// for the full run and a scripted verdict for the `-v -run '^Top$/^Sub$'` rerun,
// and records every invocation so the tests can check exactly what was rerun.

const fakeGoScript = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_GO_LOG"
case " $* " in
  *" -v "*)
    rx=""; prev=""
    for a in "$@"; do [ "$prev" = "-run" ] && rx="$a"; prev="$a"; done
    leaf=${rx//^/}; leaf=${leaf//\$/}; leaf=${leaf//\\/}
    case "$FAKE_RERUN" in
      pass) echo "=== RUN   $leaf"; echo "--- PASS: $leaf (0.01s)"; echo PASS; printf 'ok  \tpkg\t0.1s\n'; exit 0 ;;
      fail) echo "--- FAIL: $leaf (0.01s)"; echo FAIL; exit 1 ;;
      none) printf 'ok  \tpkg\t0.01s [no tests to run]\n'; exit 0 ;;
    esac ;;
  *) cat "$FAKE_FIRST"; exit "${FAKE_FIRST_RC:-1}" ;;
esac
`

type rerunResult struct {
	out   string
	rc    int
	calls []string // the go invocations, first run first
	sum   string   // GITHUB_STEP_SUMMARY content
}

func runRerun(t *testing.T, firstFixture, rerunVerdict string, env ...string) rerunResult {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGoScript), 0o700); err != nil { //nolint:gosec // test-only fake, must be executable
		t.Fatal(err)
	}
	work := t.TempDir()
	logPath := filepath.Join(work, "go.log")
	sumPath := filepath.Join(work, "summary.md")
	first := firstFixture
	if !filepath.IsAbs(first) {
		var err error
		if first, err = filepath.Abs(filepath.Join("testdata", "rerun", firstFixture)); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("rerun-known-flakes.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-I", script, "--label", "root-4", "--", //nolint:gosec // this repo's own script
		"go", "test", "-race", "-timeout", "1800s", "-run", "", "-shuffle=on",
		"-coverprofile=cov.out", "-covermode=atomic", "./pkg/one", "./pkg/two")
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GO_LOG="+logPath, "FAKE_FIRST="+first, "FAKE_RERUN="+rerunVerdict,
		"GITHUB_STEP_SUMMARY="+sumPath, "KNOWN_FLAKE_RERUN=1")
	cmd.Env = append(cmd.Env, env...)
	out, runErr := cmd.CombinedOutput()
	rc := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("running the wrapper: %v\n%s", runErr, out)
	}
	res := rerunResult{out: string(out), rc: rc}
	if raw, err := os.ReadFile(logPath); err == nil { //nolint:gosec // t.TempDir path
		res.calls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	if raw, err := os.ReadFile(sumPath); err == nil { //nolint:gosec // t.TempDir path
		res.sum = string(raw)
	}
	return res
}

func mustContain(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("output lacks %q:\n%s", w, got)
		}
	}
}

func TestRerunKnownFlakes_PassOnRetry(t *testing.T) {
	cases := []struct {
		fixture string
		leaves  []string // what is rerun, as -run regex
		count   string
	}{
		{"p9-first.txt", []string{`^TestPlantedDefectsDetectedByDirectedPrograms$/^P9_unbounded_decompression$`}, "attempted=1 passed=1 failed=0"},
		{"govulncheck-first.txt", []string{`^TestGovulncheckCheckScript$`}, "attempted=1 passed=1 failed=0"},
		{"edge-first.txt", []string{`^TestEdgeUnattended_InterruptedMigrationCompletes$`}, "attempted=1 passed=1 failed=0"},
		{"canary-first.txt", []string{
			`^TestCorePGCanaryOracleCatchesPlantedLeaks$/^shim\-quoting\-a\-stored\-column\-is\-reported$`,
			`^TestCorePGCanaryOracleCatchesPlantedLeaks$/^shim\-quoting\-a\-secret\-value\-is\-reported$`,
		}, "attempted=2 passed=2 failed=0"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			r := runRerun(t, tc.fixture, "pass")
			if r.rc != 0 {
				t.Fatalf("rc = %d, want 0 (the retry passed)\n%s", r.rc, r.out)
			}
			// The first failure stays in the log, untouched.
			mustContain(t, r.out, "--- FAIL: Test", "FLAKE-RERUN-COUNT leg=root-4 "+tc.count, "passed on retry [pkg=", "::warning title=FLAKE-RERUN::")
			if len(r.calls) != 1+len(tc.leaves) {
				t.Fatalf("go called %d times, want %d: %v", len(r.calls), 1+len(tc.leaves), r.calls)
			}
			first := r.calls[0]
			mustContain(t, first, "-coverprofile=cov.out", "-covermode=atomic", "./pkg/one ./pkg/two")
			for i, rx := range tc.leaves {
				rr := r.calls[1+i]
				mustContain(t, rr, "-race", "-timeout 1800s", "-shuffle=on", "-count=1", "-v", "-run "+rx)
				// The leg's coverage profile is never touched by a rerun, and the rerun
				// targets the failed package only.
				if strings.Contains(rr, "coverprofile") || strings.Contains(rr, "covermode") || strings.Contains(rr, "./pkg/") {
					t.Errorf("rerun must not carry coverage flags or the leg's package list: %s", rr)
				}
				if !strings.Contains(rr, "github.com/keyorixhq/keyorix/") {
					t.Errorf("rerun does not name the failed package: %s", rr)
				}
			}
			mustContain(t, r.sum, "FLAKE-RERUN (root-4)", "passed on retry")
		})
	}
}

func TestRerunKnownFlakes_RetryFailsFailsTheLeg(t *testing.T) {
	for _, verdict := range []string{"fail", "none"} {
		t.Run(verdict, func(t *testing.T) {
			r := runRerun(t, "p9-first.txt", verdict)
			if r.rc == 0 {
				t.Fatalf("a retry that fails or runs nothing must fail the leg\n%s", r.out)
			}
			mustContain(t, r.out, "FAILED on retry", "attempted=1 passed=0 failed=1", "::error title=FLAKE-RERUN::")
			if len(r.calls) != 2 {
				t.Fatalf("exactly one rerun expected, got calls %v", r.calls)
			}
		})
	}
}

// mutate rewrites a recorded first-run output into a temp fixture.
func mutatedFixture(t *testing.T, from string, edit func(string) string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rerun", from)) //nolint:gosec // repo testdata
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "mutated.txt")
	if err := os.WriteFile(p, []byte(edit(string(raw))), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRerunKnownFlakes_NeverRerunsWhatIsNotListed(t *testing.T) {
	cases := []struct {
		name    string
		fixture func(t *testing.T) string
		why     string
	}{
		{"another planted-defect case of the same test", func(t *testing.T) string {
			return mutatedFixture(t, "p9-first.txt", func(s string) string {
				return strings.ReplaceAll(s, "P9_unbounded_decompression", "P3_some_other_defect")
			})
		}, "is not on the known-flake list"},
		{"the whole planted-defect test failing at top level only", func(t *testing.T) string {
			return mutatedFixture(t, "p9-first.txt", func(s string) string {
				return strings.Replace(s, "    --- FAIL: TestPlantedDefectsDetectedByDirectedPrograms/P9_unbounded_decompression (15.58s)\n", "", 1)
			})
		}, "is not on the known-flake list"},
		{"a listed test name in the wrong package", func(t *testing.T) string {
			return mutatedFixture(t, "edge-first.txt", func(s string) string {
				return strings.ReplaceAll(s, "keyorix/server\t", "keyorix/server/http\t")
			})
		}, "is not on the known-flake list"},
		{"a fuzz test", func(t *testing.T) string {
			return mutatedFixture(t, "govulncheck-first.txt", func(s string) string {
				return strings.ReplaceAll(s, "TestGovulncheckCheckScript", "FuzzAuthzSeq")
			})
		}, "is not on the known-flake list"},
		{"a DATA RACE next to a listed test", func(t *testing.T) string {
			return mutatedFixture(t, "govulncheck-first.txt", func(s string) string {
				return strings.Replace(s, "--- FAIL:", "WARNING: DATA RACE\n--- FAIL:", 1)
			})
		}, "DATA RACE"},
		{"a panic next to a listed test", func(t *testing.T) string {
			return mutatedFixture(t, "edge-first.txt", func(s string) string {
				return strings.Replace(s, "FAIL\nFAIL", "panic: boom\nFAIL\nFAIL", 1)
			})
		}, "panic: boom"},
		{"a test timeout", func(t *testing.T) string {
			return mutatedFixture(t, "edge-first.txt", func(s string) string {
				return strings.Replace(s, "FAIL\nFAIL", "panic: test timed out after 30m0s\nFAIL\nFAIL", 1)
			})
		}, "test timed out"},
		{"a build failure", func(t *testing.T) string {
			return mutatedFixture(t, "edge-first.txt", func(s string) string {
				return "FAIL\tgithub.com/keyorixhq/keyorix/server [build failed]\n"
			})
		}, "build or setup failed"},
		{"listed test plus an unlisted one in another package", func(t *testing.T) string {
			return mutatedFixture(t, "p9-first.txt", func(s string) string {
				return s + "--- FAIL: TestSomethingReal (0.10s)\nFAIL\nFAIL\tgithub.com/keyorixhq/keyorix/internal/other\t1.0s\n"
			})
		}, "TestSomethingReal is not on the known-flake list"},
		{"no failing test in the output", func(t *testing.T) string {
			return mutatedFixture(t, "p9-first.txt", func(s string) string {
				return "FAIL\tgithub.com/keyorixhq/keyorix/internal/fuzzutil/hostile\t72.1s\n"
			})
		}, "no parsable"},
		{"more than five listed tests", func(t *testing.T) string {
			return mutatedFixture(t, "canary-first.txt", func(s string) string {
				var b strings.Builder
				b.WriteString("--- FAIL: TestCorePGCanaryOracleCatchesPlantedLeaks (6.56s)\n")
				for i := range 6 {
					b.WriteString("    --- FAIL: TestCorePGCanaryOracleCatchesPlantedLeaks/case-" + string(rune('a'+i)) + " (0.1s)\n")
				}
				b.WriteString("FAIL\nFAIL\tgithub.com/keyorixhq/keyorix/internal/core\t679.278s\n")
				return b.String()
			})
		}, "more than 5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runRerun(t, tc.fixture(t), "pass")
			if r.rc != 1 {
				t.Fatalf("rc = %d, want the first run's 1\n%s", r.rc, r.out)
			}
			mustContain(t, r.out, "FLAKE-RERUN not attempted", tc.why, "attempted=0")
			if len(r.calls) != 1 {
				t.Fatalf("nothing may be rerun, go calls: %v", r.calls)
			}
		})
	}
}

func TestRerunKnownFlakes_OffByDefault(t *testing.T) {
	r := runRerun(t, "p9-first.txt", "pass", "KNOWN_FLAKE_RERUN=")
	if r.rc != 1 || len(r.calls) != 1 || strings.Contains(r.out, "FLAKE-RERUN") {
		t.Fatalf("without KNOWN_FLAKE_RERUN=1 the wrapper is a pass-through: rc=%d calls=%v\n%s", r.rc, r.calls, r.out)
	}
}

func TestRerunKnownFlakes_GreenRunReportsZero(t *testing.T) {
	r := runRerun(t, "p9-first.txt", "pass", "FAKE_FIRST_RC=0")
	if r.rc != 0 || len(r.calls) != 1 {
		t.Fatalf("rc=%d calls=%v\n%s", r.rc, r.calls, r.out)
	}
	mustContain(t, r.out, "FLAKE-RERUN-COUNT leg=root-4 attempted=0 passed=0 failed=0")
}

// Allowlist hygiene: every entry names a real test in the named package, none is a
// fuzz test, and the planted-defect/oracle tests are exactly the two Andrei named,
// the P9 one only as its subtest (widening it to the whole test would let any planted
// defect that stops being detected pass on a coin flip).
func TestKnownFlakesAllowlist(t *testing.T) {
	raw, err := os.ReadFile("known-flakes.txt")
	if err != nil {
		t.Fatal(err)
	}
	permittedOracle := map[string]bool{
		"internal/fuzzutil/hostile TestPlantedDefectsDetectedByDirectedPrograms/P9_unbounded_decompression": true,
		"internal/core TestCorePGCanaryOracleCatchesPlantedLeaks":                                           true,
	}
	oracleish := regexp.MustCompile(`Planted|Oracle|RedProof|Canary|Fuzz`)
	seen := 0
	for l := range strings.SplitSeq(string(raw), "\n") {
		l = strings.TrimSpace(strings.SplitN(l, "#", 2)[0])
		if l == "" {
			continue
		}
		seen++
		f := strings.Fields(l)
		if len(f) != 2 {
			t.Errorf("entry %q: want '<package> <test>'", l)
			continue
		}
		pkg, test := f[0], f[1]
		top, _, _ := strings.Cut(test, "/")
		if strings.HasPrefix(top, "Fuzz") {
			t.Errorf("entry %q: a fuzz test is never rerun", l)
		}
		if oracleish.MatchString(test) && !permittedOracle[l] {
			t.Errorf("entry %q: an oracle/planted-defect test may be listed only as the one named in MQ-LEVERS-2", l)
		}
		files, _ := filepath.Glob(filepath.Join("..", "..", pkg, "*_test.go"))
		found := false
		for _, file := range files {
			b, err := os.ReadFile(file) //nolint:gosec // repo files
			if err == nil && strings.Contains(string(b), "func "+top+"(t *testing.T)") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("entry %q: no `func %s(t *testing.T)` in %s/*_test.go (renamed or removed: delete the entry)", l, top, pkg)
		}
	}
	if seen == 0 {
		t.Fatal("known-flakes.txt has no entries")
	}
	for want := range permittedOracle {
		if !strings.Contains(string(raw), "\n"+want+"\n") {
			t.Errorf("the allowlist lost the named entry %q", want)
		}
	}
}
