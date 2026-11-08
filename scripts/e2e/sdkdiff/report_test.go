package main

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordOutcomes is the call site of the executed count (D3): a step the driver could not run
// (driver_error) or a reply that is not a protocol answer must not count, and wire requests are
// counted from the proxy records, not from driver replies.
func TestRecordOutcomesCountsAnswersAndWire(t *testing.T) {
	answer := StepOutcome{Drv: map[string]any{"ok": true, "value": "1"}, Reqs: []Rec{{Method: "GET"}, {Method: "GET"}}}
	failed := StepOutcome{Drv: map[string]any{"ok": false, "class": "other"}}
	driverErr := StepOutcome{Drv: map[string]any{"driver_error": "SDK lacks Client.health"}}
	rep := &Report{}
	rep.recordOutcomes(map[string]Outcome{
		"go":     {Steps: []StepOutcome{driverErr, answer}},
		"python": {Steps: []StepOutcome{driverErr, driverErr}},
		"node":   {Steps: []StepOutcome{failed}},
	})
	if rep.Executed["go"] != 1 || rep.Executed["node"] != 1 {
		t.Errorf("Executed = %v, want go and node 1", rep.Executed)
	}
	if rep.Executed["python"] != 0 {
		t.Errorf("a driver that only reported driver_error counted as executed: %v", rep.Executed)
	}
	if rep.Wire["go"] != 2 || rep.Wire["python"] != 0 || rep.Wire["node"] != 0 {
		t.Errorf("Wire = %v, want go 2, python 0, node 0", rep.Wire)
	}
	rep.recordOutcomes(map[string]Outcome{"go": {Steps: []StepOutcome{answer}}})
	if rep.Executed["go"] != 2 || rep.Wire["go"] != 4 {
		t.Errorf("counts must accumulate across scenarios: executed %v wire %v", rep.Executed, rep.Wire)
	}
}

// An SDK whose driver answers every step with an ordinary error but never puts a request on the wire
// exercised nothing (a renamed SDK method). Control C1 and the run check must not pass it.
func TestNoWireRequestFailsControlAndNotRun(t *testing.T) {
	silent := StepOutcome{Drv: map[string]any{"ok": false, "class": "other", "native": "AttributeError"}}
	wired := StepOutcome{Drv: map[string]any{"ok": true, "value": "1"}, Reqs: []Rec{{Method: "GET"}}}
	rep := &Report{SDKs: []string{"python", "python@2"}, Scenarios: 1, Sigs: map[string]*SigStat{}}
	rep.recordOutcomes(map[string]Outcome{
		"python":   {Steps: []StepOutcome{silent, silent}},
		"python@2": {Steps: []StepOutcome{silent, silent}},
	})
	if rep.Executed["python"] != 1 {
		t.Fatalf("premise: the silent driver must read as having answered, got %v", rep.Executed)
	}
	line, ok := controlC1(rep)
	if ok || !strings.Contains(line, "python recorded no wire request") || !strings.Contains(line, "python@2 recorded no wire request") {
		t.Errorf("control passed an SDK with no wire request: ok=%v %q", ok, line)
	}
	if p := rep.notRun(); len(p) != 2 {
		t.Errorf("notRun = %v, want one entry per silent SDK", p)
	}

	// green direction: the same shape with requests recorded passes
	rep = &Report{SDKs: []string{"python", "python@2"}, Scenarios: 1, Sigs: map[string]*SigStat{}}
	rep.recordOutcomes(map[string]Outcome{
		"python":   {Steps: []StepOutcome{wired}},
		"python@2": {Steps: []StepOutcome{wired}},
	})
	if line, ok := controlC1(rep); !ok {
		t.Errorf("wired run failed the control: %q", line)
	}
}

// A scenario set whose steps are all constructor checks makes no request by design, so a run over it
// must not be refused for recording no wire request (F2). The decision comes from the scenarios, never
// from driver output: a set with any other step still requires the wire, and a report that does not
// say (an older baseline) keeps requiring it.
func TestWireRequiredOnlyWhenScenariosNeedIt(t *testing.T) {
	construct := Scenario{ID: "c1", Steps: []Step{{Op: "construct", Base: "literal:https://example.com"}}}
	call := Scenario{ID: "s1", Steps: []Step{{Op: "construct", Base: "plain"}, {Op: "health"}}}
	if scenariosNeedWire([]Scenario{construct, construct}) {
		t.Error("a construct-only set was said to need the wire")
	}
	if !scenariosNeedWire([]Scenario{construct, call}) {
		t.Error("a set with a non-construct step was said not to need the wire")
	}
	if !scenariosNeedWire(nil) {
		t.Error("an empty set must default to requiring the wire")
	}

	silent := StepOutcome{Drv: map[string]any{"ok": true, "value": "1"}}
	run := func(noWire bool) *Report {
		rep := &Report{SDKs: []string{"go", "node"}, Scenarios: 2, Sigs: map[string]*SigStat{}, NoWireNeeded: noWire}
		o := map[string]Outcome{"go": {Steps: []StepOutcome{silent}}, "node": {Steps: []StepOutcome{silent}}}
		rep.recordOutcomes(o)
		rep.recordOutcomes(o)
		return rep
	}
	// green: a construct-only run with no requests is a valid run and a valid control
	rep := run(true)
	if p := rep.notRun(); len(p) != 0 {
		t.Errorf("construct-only run refused: %v", p)
	}
	if line, ok := controlC1(rep); !ok {
		t.Errorf("construct-only control failed: %q", line)
	}
	// red: the same outputs over scenarios that need the wire are still refused
	rep = run(false)
	if p := rep.notRun(); len(p) != 2 {
		t.Errorf("notRun = %v, want one 'no wire request' entry per SDK", p)
	}
	// even with no wire needed, an SDK that answered nothing is still not run
	rep = &Report{SDKs: []string{"go"}, Scenarios: 1, NoWireNeeded: true, Sigs: map[string]*SigStat{}}
	if p := rep.notRun(); len(p) != 1 || !strings.Contains(p[0], "executed no step") {
		t.Errorf("notRun = %v, want 'executed no step'", p)
	}
}

// A driver whose SDK lacks a method it calls must answer driver_error (a harness failure), whatever
// the command, and must keep working when the SDK is intact. The fake SDK checkouts below define every
// function the driver looks for; the renamed copy renames one method.
func TestDriversReportMissingSDKMethodAsDriverError(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	pyMethods := []string{"health", "list_secrets_scoped", "get_secret_scoped", "get_secret_in", "get_secret_by_ref",
		"list_deleted_secrets", "list_projects", "create_project", "list_environments"}
	jsMethods := []string{"health", "listSecretsScoped", "getSecretScoped", "getSecretIn", "getSecretByRef",
		"listDeletedSecrets", "listProjects", "createProject", "listEnvironments"}
	pySDK := func(rename string) string {
		var b strings.Builder
		b.WriteString("def login(*a, **k):\n    return 'tok'\n\n\nclass Client:\n    def __init__(self, *a, **k):\n        pass\n")
		for _, m := range pyMethods {
			if m == rename {
				m += "_renamed"
			}
			b.WriteString("\n    def " + m + "(self, *a, **k):\n        return True\n")
		}
		return b.String()
	}
	jsSDK := func(rename string) string {
		var b strings.Builder
		b.WriteString("'use strict';\nasync function login() { return 'tok'; }\nclass Client {\n  constructor() {}\n")
		for _, m := range jsMethods {
			if m == rename {
				m += "R"
			}
			b.WriteString("  async " + m + "() { return true; }\n")
		}
		b.WriteString("}\nmodule.exports = { login, Client };\n")
		return b.String()
	}
	cases := []struct {
		kind, bin, file string
		sdk             func(string) string
		renamed         string
	}{
		{"python", "python3", filepath.Join("python", "keyorix.py"), pySDK, "list_projects"},
		{"node", "node", filepath.Join("node", "keyorix.js"), jsSDK, "listProjects"},
	}
	// "health" is the cheapest command; a renamed list_projects must fail it too, since the check is up front.
	line := "health\t" + hex.EncodeToString([]byte("http://127.0.0.1:9")) + "\t~\t0"
	for _, c := range cases {
		if _, err := exec.LookPath(c.bin); err != nil {
			t.Logf("%s: %s not installed, skipped", c.kind, c.bin)
			continue
		}
		for name, rename := range map[string]string{"intact": "", "renamed": c.renamed} {
			sdks := t.TempDir()
			path := filepath.Join(sdks, c.file)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(c.sdk(rename)), 0o600); err != nil {
				t.Fatal(err)
			}
			d, err := DriverSet{Root: root, SDKsDir: sdks}.make(c.kind)
			if err != nil {
				t.Fatal(err)
			}
			got, err := d.call(line, 20*time.Second)
			d.kill()
			if err != nil {
				t.Fatalf("%s %s: %v", c.kind, name, err)
			}
			_, isDriverErr := got["driver_error"]
			if name == "renamed" && !isDriverErr {
				t.Errorf("%s: a renamed %s did not produce driver_error: %v", c.kind, c.renamed, got)
			}
			if name == "intact" && (isDriverErr || got["ok"] != true) {
				t.Errorf("%s: an intact SDK was refused: %v", c.kind, got)
			}
			if name == "renamed" && isDriverErr && !strings.Contains(got["driver_error"].(string), c.renamed) {
				t.Errorf("%s: driver_error does not name the missing method: %v", c.kind, got)
			}
		}
	}
}
