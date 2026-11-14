package configspace

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests drive the process stage and the whole campaign loop against a stand-in
// "server" written as a shell script, so they need no real keyorix-server binary. The
// scripts only imitate what RunProc looks at (a listening line, a signal, an exit code).

func fakeServer(t *testing.T, name, body string) string {
	t.Helper()
	if _, err := exec.LookPath("nice"); err != nil {
		t.Skip("nice not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil { // #nosec G306 -- executable test stand-in in a private temp dir
		t.Fatal(err)
	}
	return p
}

func procCase(t *testing.T) *Case {
	t.Helper()
	dir := t.TempDir()
	return &Case{
		ID: "proc", Kind: "solo", Dir: dir,
		Env: map[string]string{"KEYORIX_CONFIG_PATH": filepath.Join(dir, "keyorix.yaml")},
		Doc: map[string]any{},
	}
}

func TestRunProcRefusal(t *testing.T) {
	bin := fakeServer(t, "refuse", "echo 'invalid configuration: refused' >&2\nexit 2\n")
	res := RunProc(bin, procCase(t), true, false, 5*time.Second, 5*time.Second)
	if res.Started || res.TimedOut || res.Exit != 2 || res.Signal != "" || !strings.Contains(res.Log, "refused") {
		t.Fatalf("refusal result = %+v", res)
	}
}

func TestRunProcCrashIsReportedAsASignal(t *testing.T) {
	bin := fakeServer(t, "crash", "kill -SEGV $$\nsleep 5\n")
	res := RunProc(bin, procCase(t), true, false, 5*time.Second, 5*time.Second)
	if res.Started || res.Signal == "" || res.Exit != -1 {
		t.Fatalf("crash result = %+v", res)
	}
}

func TestRunProcHangIsKilledAndReported(t *testing.T) {
	bin := fakeServer(t, "hang", "exec sleep 30\n")
	start := time.Now()
	res := RunProc(bin, procCase(t), true, false, 400*time.Millisecond, time.Second)
	if !res.TimedOut || res.Started {
		t.Fatalf("hang result = %+v", res)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("RunProc did not return promptly after the start window")
	}
}

func TestRunProcStartProbeAndGracefulStop(t *testing.T) {
	bin := fakeServer(t, "start", `if [ "$1" = "admin" ]; then echo "admin ok $*"; exit 0; fi
trap 'echo "All servers shut down gracefully"; kill $pid 2>/dev/null; exit 0' TERM
sleep 30 &
pid=$!
echo "HTTP server listening on http://127.0.0.1:1"
echo "gRPC server listening on 127.0.0.1:2"
wait $pid
`)
	res := RunProc(bin, procCase(t), true, true, 10*time.Second, 10*time.Second)
	if !res.Started || !res.ShutdownOK || !res.Graceful || res.Exit != 0 {
		t.Fatalf("start result = %+v", res)
	}
	if len(res.Listening) != 2 || res.Listening[0] != "http://127.0.0.1:1" || res.Listening[1] != "grpc://127.0.0.1:2" {
		t.Fatalf("listening = %v", res.Listening)
	}
	// nothing listens on port 1: the probe records the failure instead of skipping it
	if code, ok := res.Health["http://127.0.0.1:1"]; !ok || code != 0 || !strings.HasPrefix(res.Bodies["http://127.0.0.1:1/health"], "ERR ") {
		t.Fatalf("probe = health %v bodies %v", res.Health, res.Bodies)
	}
	for _, k := range []string{"admin validate --posture", "admin diagnose"} {
		if !strings.Contains(res.Admin[k], "admin ok") {
			t.Errorf("admin %q output = %q", k, res.Admin[k])
		}
	}
}

func TestRunProcStartFailure(t *testing.T) {
	res := RunProc(filepath.Join(t.TempDir(), "missing"), procCase(t), true, false, time.Second, time.Second)
	if res.Started || res.Log == "" {
		t.Fatalf("result for a missing binary = %+v", res)
	}
}

func TestExitInfoReportsExitCodes(t *testing.T) {
	bin := fakeServer(t, "three", "exit 3\n")
	err := exec.Command(bin).Run() // #nosec G204 -- the stand-in script this test just wrote
	if code, sig := exitInfo(err); code != 3 || sig != "" {
		t.Fatalf("exitInfo = %d %q", code, sig)
	}
}

// TestRunCampaignInProcessAndAgainstARefusingServer runs every stage of the campaign on
// the toy model: in-process rows, the covering arrays, the targeted I5 cases, then the
// process stage against a server that refuses everything. It proves the loop wires the
// stages together and writes its results, not that any particular finding appears.
func TestRunCampaignInProcessAndAgainstARefusingServer(t *testing.T) {
	m, tpl := toy(t), template(t)
	bin := fakeServer(t, "refuse", "echo 'invalid configuration' >&2\nexit 2\n")
	out := t.TempDir()
	var logged int
	sum, err := Run(RunOptions{
		Model: m, Template: tpl, Work: filepath.Join(t.TempDir(), "work"), Out: out, Bin: bin,
		Seed: 1, ProcInvalid: 2, Known: []KnownFinding{}, Log: func(string, ...any) { logged++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Solo != 19 || sum.Params != 8 || sum.Values != 19 {
		t.Fatalf("summary counts = %+v", sum)
	}
	rows := sum.Solo + sum.PairAll + sum.PairClean + sum.PairStart + sum.Targeted
	if got := sum.InProcAccepted + sum.InProcRefused + sum.InProcPanics; got != rows {
		t.Fatalf("in-process verdicts = %d, want one per row (%d)", got, rows)
	}
	if sum.Targeted != len(PrecedenceCases())+len(AliasCases()) || logged == 0 {
		t.Fatalf("targeted %d, logged %d", sum.Targeted, logged)
	}
	if sum.ProcRun == 0 || sum.ProcStarted != 0 || sum.ProcRefused != sum.ProcRun {
		t.Fatalf("process stage against a refusing server: %+v", sum)
	}
	b, err := os.ReadFile(filepath.Join(out, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back Summary
	if err := json.Unmarshal(b, &back); err != nil || back.Unique != sum.Unique {
		t.Fatalf("summary.json = %s (%v)", b, err)
	}
	f, err := os.ReadFile(filepath.Join(out, "findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(f), "\n"); lines != sum.Unique {
		t.Fatalf("findings.jsonl has %d lines for %d unique findings", lines, sum.Unique)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(f)), "\n") {
		if line == "" {
			continue
		}
		var u UniqueFinding
		if err := json.Unmarshal([]byte(line), &u); err != nil || u.Count == 0 || u.Known != "" {
			t.Fatalf("bad finding line %q (%v)", line, err)
		}
	}
}

func TestRunRejectsAnUnwritableOutput(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(RunOptions{Model: toy(t), Out: filepath.Join(blocker, "out"), Work: t.TempDir(), Known: []KnownFinding{}})
	if err == nil {
		t.Fatal("Run wrote into a path below a regular file")
	}
	_, err = Run(RunOptions{Model: toy(t), Out: t.TempDir(), Work: filepath.Join(blocker, "work"), Known: []KnownFinding{}})
	if err == nil {
		t.Fatal("Run used a work directory below a regular file")
	}
}

func TestExplainedRefusalAndEnabledFlags(t *testing.T) {
	m := toy(t)
	c := &Case{Doc: map[string]any{}}
	if !explainedRefusal(m, c, "c.d is required") || explainedRefusal(m, c, "unrelated") {
		t.Fatal("explainedRefusal must name the triggered conflict's option")
	}
	if explainedRefusal(m, &Case{Doc: map[string]any{"c": map[string]any{"d": 1}}}, "c.d") {
		t.Fatal("no conflict triggered, so nothing explains the refusal")
	}
	doc := map[string]any{"server": map[string]any{"http": map[string]any{"enabled": true}, "grpc": map[string]any{"enabled": false}}}
	if h, g := enabledFlags(&Case{Doc: doc}, InProcResult{}); !h || g {
		t.Fatalf("enabledFlags from the document = %v %v", h, g)
	}
}
