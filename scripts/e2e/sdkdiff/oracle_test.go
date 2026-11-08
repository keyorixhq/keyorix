package main

import (
	"os"
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
	rep = &Report{SDKs: []string{"go", "go@2"}, Scenarios: 2, Executed: map[string]int{"go": 2, "go@2": 2}, Sigs: map[string]*SigStat{}}
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
		Sigs: map[string]*SigStat{"x": {First: Finding{Blocks: [][]string{{"go"}, {"go@2"}}}}}}
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
