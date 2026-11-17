package main

// The hostile-mode orchestrator end to end with a stub driver: a shell script that answers every call line with one
// JSON object, standing in for the Go SDK driver (<build>/driver-go). It never talks to the mock server, so every
// record is "not-reached"; what is exercised is the matrix, the C0 golden pass, the result files and the report.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func stubBuild(t *testing.T, script string) string {
	t.Helper()
	for _, bin := range []string{"sh", "nice"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "driver-go"), []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatal(err)
	}
	return dir
}

func TestHostileRunWithAStubDriver(t *testing.T) {
	build := stubBuild(t, `while read l; do echo '{"ok":true,"value":"v"}'; done`)
	out := filepath.Join(t.TempDir(), "res")
	var runErr error
	stdout := captureStdout(t, func() {
		// D0* is 9 mutations over 12 scenarios: more than 100 jobs, so the progress line is printed too
		runErr = hostileRun([]string{"-sdks", "go", "-build", build, "-root", t.TempDir(), "-sdks-dir", t.TempDir(), "-out", out, "-mut", "D0", "-label", "stub", "-par", "0"})
	})
	if runErr != nil {
		t.Fatalf("hostileRun: %v", runErr)
	}
	if !strings.Contains(stdout, "hostile run: ") || !strings.Contains(stdout, "label=stub") || !strings.Contains(stdout, "== hostile report stub") {
		t.Errorf("stdout lacks the run header or the report:\n%s", trunc(stdout, 400))
	}
	recs, err := loadResults(out)
	if err != nil {
		t.Fatal(err)
	}
	// 13 control calls plus one per job (the job list has no C0 entry)
	wantJobs := len(buildJobs(selectMuts("D0"), ""))
	if len(recs) != len(hscens)+wantJobs {
		t.Errorf("%d records, want %d control + %d jobs", len(recs), len(hscens), wantJobs)
	}
	for _, r := range recs {
		if r.SDK != "go" || r.Applied != "not-reached" || r.Outcome != "ok" {
			t.Fatalf("unexpected record %+v", r)
		}
		if r.Drv != nil {
			t.Fatalf("driver detail must be trimmed from stored records: %+v", r)
		}
	}
	if rep, err := os.ReadFile(filepath.Join(out, "report.txt")); err != nil || !strings.Contains(string(rep), "go      runs=") {
		t.Errorf("report.txt: %v %q", err, trunc(string(rep), 100))
	}
}

func TestHostileRunReportsAnUnknownSDK(t *testing.T) {
	out := filepath.Join(t.TempDir(), "res")
	var runErr error
	_ = captureStdout(t, func() {
		runErr = hostileRun([]string{"-sdks", "cobol", "-out", out, "-mut", "C0"})
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "cobol") || !strings.Contains(runErr.Error(), "unknown SDK kind") {
		t.Fatalf("hostileRun error = %v", runErr)
	}
	if _, err := os.Stat(filepath.Join(out, "results.jsonl")); err != nil {
		t.Errorf("results are written even when an SDK fails to start: %v", err)
	}
}

func TestHostileReplayWithAStubDriver(t *testing.T) {
	build := stubBuild(t, `while read l; do echo '{"ok":false,"class":"parse","native":"E","sdk_error":true,"msg":"nope"}'; done`)
	var err error
	stdout := captureStdout(t, func() {
		err = hostileReplay([]string{"-sdks-dir", t.TempDir(), "-build", build, "-root", t.TempDir(), "-triples", "go:S03:D04,go:S06:R01", "-n", "2"})
	})
	if err != nil {
		t.Fatalf("hostileReplay: %v", err)
	}
	for _, want := range []string{"go      S03  D04   repeats=2 identical=true", "go      S06  R01   repeats=2 identical=true", "outcome=err:parse"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("replay output lacks %q:\n%s", want, stdout)
		}
	}
	if err := hostileReplay([]string{"-sdks-dir", t.TempDir(), "-build", build, "-root", t.TempDir(), "-triples", "cobol:S03:D04"}); err == nil {
		t.Error("replay of an unknown SDK must fail")
	}
}

func TestStubDriverThatDiesIsRecordedNotFatal(t *testing.T) {
	build := stubBuild(t, `read l; exit 3`)
	var recs []RunRec
	var err error
	_ = captureStdout(t, func() {
		recs, err = runMatrix(&hostileCfg{sdks: "go", build: build, root: t.TempDir(), sdksDir: t.TempDir(), par: 1}, buildJobs(selectMuts("D04"), "S03"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	for _, r := range recs {
		if r.Outcome != "harness" && r.Outcome != "died" {
			t.Errorf("a dying driver must be a recorded outcome, got %+v", r)
		}
	}
}
