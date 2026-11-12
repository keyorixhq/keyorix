package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func countCat(fs []Finding, cat, shape string) int {
	n := 0
	for _, f := range fs {
		if f.Cat == cat && (shape == "" || f.Shape == shape) {
			n++
		}
	}
	return n
}

// X1 must flag a credential in the body of a request that reached the other origin, not only an
// Authorization header (login sends its credential in the body).
func TestX1FlagsCredentialInBodyAtOtherOrigin(t *testing.T) {
	tok := func(string) string { return "session-token-0123456789" }
	rec := func(host, body string) Rec {
		return Rec{Method: "POST", RequestURI: "/sink", Header: map[string][]string{"Host": {host}}, Body: []byte(body)}
	}
	check := func(r Rec) []Finding {
		return absoluteChecks("s", 0, Step{Op: "login"}, []view{{sdk: "go", ok: true, recs: []Rec{r}}}, nil, tok)
	}
	pw := `{"username":"u","password":"` + adminPW + `"}`
	if n := countCat(check(rec("localhost:9", pw)), "X1", "credential-in-body-sent-to-other-origin"); n != 1 {
		t.Errorf("password in body at other origin: %d X1 findings, want 1", n)
	}
	if n := countCat(check(rec("localhost:9", `{"t":"session-token-0123456789"}`)), "X1", ""); n != 1 {
		t.Errorf("token in body at other origin: %d X1 findings, want 1", n)
	}
	if n := countCat(check(rec("localhost:9", `{"username":"u"}`)), "X1", ""); n != 0 {
		t.Errorf("body without credential: %d X1 findings, want 0", n)
	}
	if n := countCat(check(rec("127.0.0.1:9", pw)), "X1", ""); n != 0 {
		t.Errorf("password at the original origin: %d X1 findings, want 0", n)
	}
	hdr := rec("localhost:9", "")
	hdr.Header["Authorization"] = []string{"Bearer x"}
	if n := countCat(check(hdr), "X1", "authorization-sent-to-other-origin"); n != 1 {
		t.Errorf("Authorization at other origin: %d X1 findings, want 1", n)
	}
}

// A run in which nothing executed must not read as a pass.
func TestControlC1FailsWhenNothingRan(t *testing.T) {
	rep := &Report{SDKs: []string{"go", "go@2"}, Scenarios: 2, Executed: map[string]int{}, Sigs: map[string]*SigStat{}}
	rep.BatchErrors = 1
	rep.Harness = []string{"H1 batch error: no such server binary"}
	line, ok := controlC1(rep)
	if ok || !strings.HasPrefix(line, "CONTROL C1 FAIL") {
		t.Fatalf("nothing ran, got ok=%v %q", ok, line)
	}
	if len(rep.notRun()) == 0 {
		t.Error("notRun is empty for a run with a failed batch and no executed SDK")
	}

	// green direction: everything ran, no harness note, no finding
	rep = &Report{SDKs: []string{"go", "go@2"}, Scenarios: 2, Executed: map[string]int{"go": 2, "go@2": 2},
		Wire: map[string]int{"go": 4, "go@2": 4}, Sigs: map[string]*SigStat{}}
	if line, ok := controlC1(rep); !ok {
		t.Fatalf("complete clean run failed: %q", line)
	}
	if p := rep.notRun(); len(p) != 0 {
		t.Errorf("notRun = %v for a complete run", p)
	}

	// one SDK silent (e.g. a driver that cannot start) is not a pass either
	rep.Executed["go@2"] = 0
	if line, ok := controlC1(rep); ok || !strings.Contains(line, "go@2 executed no step") {
		t.Errorf("silent SDK: ok=%v %q", ok, line)
	}

	// a split twin still fails
	rep = &Report{SDKs: []string{"go", "go@2"}, Scenarios: 1, Executed: map[string]int{"go": 1, "go@2": 1},
		Wire: map[string]int{"go": 1, "go@2": 1}, Sigs: map[string]*SigStat{"x": {First: Finding{Blocks: [][]string{{"go"}, {"go@2"}}}}}}
	if _, ok := controlC1(rep); ok {
		t.Error("split twins passed")
	}
}

func TestPlantedIsOddOneOut(t *testing.T) {
	cases := []struct {
		name   string
		blocks [][]string
		want   bool
	}{
		{"singleton", [][]string{{"go", "node"}, {"python"}}, true},
		{"majority block", [][]string{{"go"}, {"node", "python"}}, false},
		{"even split", [][]string{{"python", "java"}, {"go", "node"}}, false},
		{"no divergence", [][]string{{"go", "node", "python"}}, false},
	}
	for _, c := range cases {
		if got := plantedIsOddOneOut(c.blocks, "python"); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// After a non-JSON line the driver is killed, so a buffered real reply cannot be read as the answer
// to the next step.
func TestDriverKilledAfterNonJSONLine(t *testing.T) {
	d := &Driver{Name: "x", argv: []string{"sh", "-c", `while read l; do echo notjson; echo '{"a":1}'; done`}, env: []string{"PATH=" + os.Getenv("PATH")}}
	defer d.kill()
	if _, err := d.call("first", 10e9); err == nil {
		t.Fatal("non-JSON line did not fail the call")
	}
	if d.cmd != nil {
		t.Error("driver still running after a protocol error")
	}
}

func TestRunnerRefusesMissingSeedManifest(t *testing.T) {
	c := common{snapshot: t.TempDir(), sdks: "go"}
	if _, err := c.runner(); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("missing sdkdiff-seed.json: err = %v", err)
	}
}

// A driver that answers only driver_error exercised nothing: it is a harness note, and the scenario
// does not count as executed (an SDK method rename produces exactly this).
func TestDriverErrorIsHarnessNoteAndNotExecuted(t *testing.T) {
	de := StepOutcome{Drv: map[string]any{"driver_error": "no such method"}}
	ok := StepOutcome{Drv: map[string]any{"ok": true, "value": "1"}}
	for _, so := range []StepOutcome{{Drv: map[string]any{"na": true}}, {Drv: map[string]any{"inexpressible": true}}, ok} {
		if !answered(so) {
			t.Errorf("%v is a protocol answer", so.Drv)
		}
	}
	for _, so := range []StepOutcome{de, {}} {
		if answered(so) {
			t.Errorf("%v counted as an answer", so.Drv)
		}
	}
	r := &Runner{SDKs: []string{"python", "python@2"}}
	_, h := r.Analyse(Scenario{ID: "s", Steps: []Step{{Op: "list_projects"}}}, map[string]Outcome{
		"python":   {Steps: []StepOutcome{de}},
		"python@2": {Steps: []StepOutcome{de}},
	})
	if len(h) != 2 {
		t.Fatalf("want one harness note per SDK, got %v", h)
	}
	rep := &Report{SDKs: r.SDKs, Scenarios: 1, Executed: map[string]int{}, Sigs: map[string]*SigStat{}, Harness: h}
	if line, pass := controlC1(rep); pass {
		t.Errorf("control passed with driver_error only: %q", line)
	}
	// the harness-note clause alone must fail the control (every other clause satisfied)
	rep = &Report{SDKs: r.SDKs, Scenarios: 1, Executed: map[string]int{"python": 1, "python@2": 1},
		Wire: map[string]int{"python": 1, "python@2": 1}, Sigs: map[string]*SigStat{}, Harness: h}
	if line, pass := controlC1(rep); pass || !strings.Contains(line, "harness note") {
		t.Errorf("harness notes alone: pass=%v %q", pass, line)
	}
}

// After a step diverges, later steps are not compared between SDKs and only E3 and X1 are still
// reported (L3): R1 at step 0 and X1 at step 2 are kept, S2 at step 1 is dropped.
func TestAnalyseAfterDivergenceKeepsOnlyCredentialOracles(t *testing.T) {
	val := func(v string) StepOutcome { return StepOutcome{Drv: map[string]any{"ok": true, "value": v}} }
	failed := StepOutcome{Drv: map[string]any{"ok": false, "error": map[string]any{"class": "server", "status": json.Number("500")}}}
	leak := val("1")
	leak.Reqs = []Rec{{Method: "GET", RequestURI: "/x", Header: map[string][]string{"Host": {"localhost:9"}, "Authorization": {"Bearer t"}}}}
	r := &Runner{SDKs: []string{"go", "node"}}
	fs, h := r.Analyse(Scenario{ID: "s", Steps: []Step{{Op: "list_projects"}, {Op: "list_projects", Expect: "ok"}, {Op: "list_projects"}}},
		map[string]Outcome{
			"go":   {Steps: []StepOutcome{val("1"), failed, leak}},
			"node": {Steps: []StepOutcome{val("2"), val("1"), val("1")}},
		})
	if len(h) != 0 {
		t.Fatalf("harness notes: %v", h)
	}
	if countCat(fs, "R1", "") == 0 {
		t.Errorf("no R1 at the diverging step: %+v", fs)
	}
	if n := countCat(fs, "S2", ""); n != 0 {
		t.Errorf("S2 after divergence not suppressed: %d", n)
	}
	if n := countCat(fs, "X1", ""); n != 1 {
		t.Errorf("X1 after divergence: %d findings, want 1", n)
	}
}

// A baseline that compared less than the plant run must not be used: its missing signatures would
// read as new (N2).
func TestBaselineProblem(t *testing.T) {
	sdks := []string{"go", "node"}
	good := func() *Report {
		return &Report{SDKs: sdks, Scenarios: 2, Executed: map[string]int{"go": 2, "node": 2}, Wire: map[string]int{"go": 3, "node": 3}}
	}
	if why := baselineProblem(good(), sdks, 2); why != "" {
		t.Errorf("genuine baseline refused: %s", why)
	}
	failedBatch := good()
	failedBatch.BatchErrors = 2
	failedBatch.Executed = map[string]int{}
	silent := good()
	silent.Executed["node"] = 0
	withHarness := good()
	withHarness.Harness = []string{"H2 driver_error: s1 go step 3"}
	for name, b := range map[string]*Report{"failed batch": failedBatch, "silent sdk": silent, "harness note": withHarness,
		"other sdks":           {SDKs: []string{"go"}, Scenarios: 2, Executed: map[string]int{"go": 2}},
		"other scenario count": {SDKs: sdks, Scenarios: 1, Executed: map[string]int{"go": 1, "node": 1}}} {
		if why := baselineProblem(b, sdks, 2); why == "" {
			t.Errorf("%s: baseline accepted", name)
		}
	}
}

// cmdValidate must stop on a baseline that compared less than the plant run, before it starts any server.
// A test of baselineProblem alone passes whether or not the function is called (D1).
func TestCmdValidateRefusesUnusableBaseline(t *testing.T) {
	dir := t.TempDir()
	scs := filepath.Join(dir, "scenarios.jsonl")
	if err := os.WriteFile(scs, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// What a run with a missing server leaves behind: a failed batch, nothing executed, no signatures.
	bad := &Report{SDKs: []string{"go", "node"}, Scenarios: 1, BatchErrors: 1,
		Executed: map[string]int{}, Sigs: map[string]*SigStat{}}
	raw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "report.json")
	if err := os.WriteFile(base, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdValidate([]string{"-in", scs, "-baseline", base, "-plants", "P3", "-sdks", "go,node", "-out", dir})
	if err == nil || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("cmdValidate accepted a baseline that compared nothing: err=%v", err)
	}
	if _, err := loadBaseline(base, []string{"go", "node"}, 1); err == nil {
		t.Error("loadBaseline accepted it")
	}
	good := &Report{SDKs: []string{"go", "node"}, Scenarios: 1, Executed: map[string]int{"go": 1, "node": 1},
		Wire: map[string]int{"go": 1, "node": 1}}
	raw, _ = json.Marshal(good)
	if err := os.WriteFile(base, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(base, []string{"go", "node"}, 1); err != nil {
		t.Errorf("genuine baseline refused: %v", err)
	}
}
