package main

// Offline checks of the hostile-mode oracles, run selection, report and results files (hostile_run.go,
// hostile_json.go). Drivers are not started: the oracle input is built by hand.

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// captureStdout runs f and returns what it printed to os.Stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	func() {
		defer func() { os.Stdout = old }()
		f()
	}()
	_ = w.Close()
	return <-done
}

func appliedReqs(class string, extra ...HReq) []HReq {
	return append([]HReq{{Method: "GET", URI: "/x", Class: class, Mutated: true, AcceptGzip: true}}, extra...)
}

func violOracles(rec RunRec) []string {
	var o []string
	for _, v := range rec.Viol {
		o = append(o, v.Oracle)
	}
	return o
}

func TestJudgeHarnessLevelReasons(t *testing.T) {
	sc, m := scenByID("S03"), mutByID("D04")
	for _, tc := range []struct {
		reason, outcome, oracle string
	}{
		{"hang", "hang", "O2"}, {"rss", "rss", "O2"}, {"badout", "harness", ""}, {"oversize", "harness", ""}, {"died", "died", "O1"}, {"", "died", "O1"},
	} {
		rec := judge(sc, m, nil, callInfo{Reason: tc.reason, Exit: "exit status 1", Stderr: "boom"}, appliedReqs("P"), nil)
		if rec.Outcome != tc.outcome {
			t.Errorf("%q: outcome %q, want %q", tc.reason, rec.Outcome, tc.outcome)
		}
		if got := violOracles(rec); tc.oracle == "" && len(got) != 0 || tc.oracle != "" && !slices.Equal(got, []string{tc.oracle}) {
			t.Errorf("%q: violations %v, want [%s]", tc.reason, got, tc.oracle)
		}
	}
	// a mutation that never reached the SDK is not held against it
	rec := judge(sc, m, nil, callInfo{Reason: "hang"}, []HReq{{Class: "P"}}, nil)
	if rec.Applied != "n/a" || len(rec.Viol) != 0 {
		t.Errorf("unapplied: applied=%s viol=%v", rec.Applied, rec.Viol)
	}
	if rec := judge(sc, m, nil, callInfo{Reason: "hang"}, nil, nil); rec.Applied != "not-reached" {
		t.Errorf("no requests: applied=%s", rec.Applied)
	}
	// a token in stderr after a death is O4, except the reflecting mutation
	rec = judge(sc, m, nil, callInfo{Stderr: "x " + canary}, appliedReqs("P"), nil)
	if !slices.Contains(violOracles(rec), "O4") {
		t.Errorf("stderr leak: %v", rec.Viol)
	}
	rec = judge(sc, mutByID("S13m"), nil, callInfo{Stderr: "x " + canary}, appliedReqs("P"), nil)
	if slices.Contains(violOracles(rec), "O4") || !strings.HasPrefix(strings.Join(rec.Notes, "|"), "O4r") {
		t.Errorf("S13m stderr leak: viol=%v notes=%v", rec.Viol, rec.Notes)
	}
}

func TestJudgeDriverAnswers(t *testing.T) {
	sc := scenByID("S03")
	reqs := appliedReqs("P")
	okAns := func(v any) map[string]any { return map[string]any{"ok": true, "value": v} }
	for _, tc := range []struct {
		name    string
		mut     string
		drv     map[string]any
		info    callInfo
		golden  map[string]any
		outcome string
		oracles []string
		note    string
	}{
		{"driver error", "D04", map[string]any{"driver_error": "bad arg"}, callInfo{}, nil, "harness", nil, "H1"},
		{"not applicable", "D04", map[string]any{"na": true}, callInfo{}, nil, "na", nil, ""},
		{"inexpressible", "D04", map[string]any{"inexpressible": true}, callInfo{}, nil, "na", nil, ""},
		{"late side events", "D04", map[string]any{"ok": false, "class": "x", "sdk_error": true, "late_side_events": []any{"boom"}}, callInfo{}, nil, "err:x", nil, "H3"},
		{"R but succeeded", "D04", okAns("v"), callInfo{}, nil, "ok", []string{"O3"}, ""},
		{"R and rejected", "D04", map[string]any{"ok": false, "class": "parse", "sdk_error": true}, callInfo{}, nil, "err:parse", nil, ""},
		{"non-SDK error", "D04", map[string]any{"ok": false, "class": "parse", "native": "TypeError", "sdk_error": false, "msg": "x"}, callInfo{}, nil, "err:parse", []string{"O1"}, ""},
		{"side event", "D04", map[string]any{"ok": false, "class": "parse", "sdk_error": true, "side_events": []any{"spawned"}}, callInfo{}, nil, "err:parse", []string{"O1"}, ""},
		{"slow", "D04", map[string]any{"ok": false, "class": "parse", "sdk_error": true}, callInfo{Elapsed: hWallDeadline + time.Second}, nil, "err:parse", []string{"O2"}, ""},
		{"big RSS", "D04", map[string]any{"ok": false, "class": "parse", "sdk_error": true}, callInfo{PeakKB: hRSSCeilingKB + 1}, nil, "err:parse", []string{"O2"}, ""},
		{"token in msg", "D04", map[string]any{"ok": false, "class": "x", "sdk_error": true, "msg": canary}, callInfo{}, nil, "err:x", []string{"O4"}, ""},
		{"token in native", "D04", map[string]any{"ok": false, "class": "x", "sdk_error": true, "native": "%2D" + strings.ReplaceAll(canary, "-", "%2D")}, callInfo{}, nil, "err:x", []string{"O4"}, ""},
		{"token in stderr only", "D04", map[string]any{"ok": false, "class": "x", "sdk_error": true}, callInfo{Stderr: canary}, nil, "err:x", []string{"O4"}, ""},
		{"A same result", "C0", okAns("v"), callInfo{}, okAns("v"), "ok", nil, ""},
		{"A changed result", "C0", okAns("w"), callInfo{}, okAns("v"), "ok", []string{"O3"}, ""},
		{"A rejected", "C0", map[string]any{"ok": false, "class": "parse", "sdk_error": true, "msg": "why"}, callInfo{}, nil, "err:parse", nil, "unexpected rejection"},
		{"X right name", "U09", okAns([]any{map[string]any{"name": "ab\x00cd"}}), callInfo{}, nil, "ok", nil, ""},
		{"X wrong name", "U09", okAns([]any{map[string]any{"name": "ab"}}), callInfo{}, nil, "ok", []string{"O3"}, ""},
		{"X rejected is fine", "U09", map[string]any{"ok": false, "class": "parse", "sdk_error": true}, callInfo{}, nil, "err:parse", nil, ""},
		{"X right id", "I01", okAns([]any{map[string]any{"id": json.Number("9007199254740993")}}), callInfo{}, nil, "ok", nil, ""},
		{"X wrong id", "I01", okAns([]any{map[string]any{"id": json.Number("9007199254740992")}}), callInfo{}, nil, "ok", []string{"O6"}, ""},
		{"X no success acceptable", "I10", okAns([]any{map[string]any{"id": json.Number("1")}}), callInfo{}, nil, "ok", []string{"O6"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := judge(sc, mutByID(tc.mut), tc.drv, tc.info, reqs, tc.golden)
			if rec.Outcome != tc.outcome {
				t.Errorf("outcome %q, want %q (%+v)", rec.Outcome, tc.outcome, rec)
			}
			if got := violOracles(rec); !slices.Equal(got, tc.oracles) {
				t.Errorf("violations %v, want %v", got, tc.oracles)
			}
			if tc.note != "" && !strings.Contains(strings.Join(rec.Notes, "|"), tc.note) {
				t.Errorf("notes %v lack %q", rec.Notes, tc.note)
			}
		})
	}
}

func TestJudgeExpectationOverrides(t *testing.T) {
	ans := map[string]any{"ok": true, "value": "v"}
	// H09 is R unless the SDK advertised gzip, then it is a benign variant
	rec := judge(scenByID("S03"), mutByID("H09"), ans, callInfo{}, appliedReqs("P"), nil)
	if rec.Exp != "A" || len(rec.Viol) != 0 {
		t.Errorf("H09 with Accept-Encoding gzip: exp=%s viol=%v", rec.Exp, rec.Viol)
	}
	// the health scenario reads the status only, so a body mutation is E there
	rec = judge(scenByID("S01"), mutByID("D04"), ans, callInfo{}, appliedReqs("H"), nil)
	if rec.Exp != "E" || len(rec.Viol) != 0 {
		t.Errorf("S01/D04: exp=%s viol=%v", rec.Exp, rec.Viol)
	}
	// login returns only a token length, so X degrades to E
	rec = judge(scenByID("S02"), mutByID("U09"), ans, callInfo{}, appliedReqs("A"), nil)
	if rec.Exp != "E" {
		t.Errorf("S02/U09: exp=%s", rec.Exp)
	}
	// an unapplied mutation records the outcome and judges nothing
	rec = judge(scenByID("S03"), mutByID("D04"), ans, callInfo{}, []HReq{{Class: "P"}}, nil)
	if rec.Applied != "n/a" || len(rec.Viol) != 0 || rec.Outcome != "ok" {
		t.Errorf("unapplied: %+v", rec)
	}
}

func TestForwardedIDOracle(t *testing.T) {
	cases := []struct {
		scen, mut, uri, class string
		wantViol              bool
	}{
		{"S11", "I01", "/api/v1/projects/9007199254740993/environments?x=1", "E", false},
		{"S11", "I01", "/api/v1/projects/9007199254740992/environments", "E", true},
		{"S12", "I02", "/api/v1/secrets?environment_id=9223372036854775807", "L", false},
		{"S12", "I02", "/api/v1/secrets?environment_id=1", "L", true},
		{"S13", "I03", "/api/v1/secrets/9223372036854775808?v=1", "V", false},
		{"S13", "I03", "/api/v1/secrets/7", "V", true},
		{"S13", "I10", "/api/v1/secrets/7", "V", true}, // "!" accepts no forwarding at all
	}
	for _, tc := range cases {
		sc := scenByID(tc.scen)
		reqs := appliedReqs(sc.Target, HReq{Class: tc.class, URI: tc.uri})
		rec := judge(sc, mutByID(tc.mut), map[string]any{"ok": false, "class": "x", "sdk_error": true}, callInfo{}, reqs, nil)
		if got := slices.Contains(violOracles(rec), "O6"); got != tc.wantViol {
			t.Errorf("%s/%s %s: O6=%v, want %v (%v)", tc.scen, tc.mut, tc.uri, got, tc.wantViol, rec.Viol)
		}
	}
	// no follow-up request at all: nothing to judge
	if id, seen := observedID(scenByID("S11"), appliedReqs("P")); seen || id != "" {
		t.Errorf("observedID without a follow-up = %q, %v", id, seen)
	}
	if _, seen := observedID(scenByID("S03"), appliedReqs("P", HReq{Class: "E", URI: "/api/v1/projects/1/environments"})); seen {
		t.Error("only S11-S13 forward an id")
	}
	// a non-matching URI for the right class is not an observation
	if _, seen := observedID(scenByID("S12"), []HReq{{Class: "L", URI: "/api/v1/secrets"}}); seen {
		t.Error("a list request without environment_id must not count")
	}
}

func TestExactOracleShapes(t *testing.T) {
	var got []string
	rec := func(o, sev, d string) { got = append(got, o+":"+sev) }
	// S04: create_project returns one object
	checkExact(scenByID("S04"), &Mut{WantID: "5"}, map[string]any{"value": map[string]any{"id": json.Number("6")}}, true, nil, rec, "MEDIUM")
	checkExact(scenByID("S04"), &Mut{WantMain: "cap1"}, map[string]any{"value": map[string]any{"name": "other"}}, true, nil, rec, "MEDIUM")
	checkExact(scenByID("S04"), &Mut{WantMain: "cap1"}, map[string]any{"value": map[string]any{"name": "cap1"}}, true, nil, rec, "MEDIUM")
	// a value-class scenario returns the string itself
	checkExact(scenByID("S07"), &Mut{WantMain: "s3cret"}, map[string]any{"value": "wrong"}, true, nil, rec, "HIGH")
	// S11-S13 are judged on the forwarded id, never on the return value
	checkExact(scenByID("S11"), &Mut{WantID: "5"}, map[string]any{"value": "x"}, true, nil, rec, "MEDIUM")
	// a mutation with no expectation checks nothing; a failed call has nothing to check
	checkExact(scenByID("S03"), &Mut{}, map[string]any{"value": "x"}, true, nil, rec, "MEDIUM")
	checkExact(scenByID("S03"), &Mut{WantMain: "x"}, map[string]any{}, false, nil, rec, "MEDIUM")
	if want := []string{"O6:MEDIUM", "O3:MEDIUM", "O3:HIGH"}; !slices.Equal(got, want) {
		t.Errorf("violations %v, want %v", got, want)
	}
}

func TestOracleHelpers(t *testing.T) {
	if str(nil) != "" || str("a") != "a" || str(json.Number("12")) != "12" || str(3) != "3" || str(true) != "true" {
		t.Error("str")
	}
	if firstOf(nil) != nil || firstOf([]any{}) != nil || firstOf([]any{"x"}) != nil || firstOf([]any{map[string]any{"a": 1}})["a"] != 1 {
		t.Error("firstOf")
	}
	if canon(map[string]any{"b": 1, "a": []any{"x"}}) != `{"a":["x"],"b":1}` {
		t.Error("canon")
	}
	if !leaksToken("x"+canary) || !leaksToken(strings.ReplaceAll(canary, "-", "%2D")) || leaksToken("clean") {
		t.Error("leaksToken")
	}
	sev := func(sc, mu string) string { return sevFor(scenByID(sc), mutByID(mu)) }
	if sev("S07", "D04") != "HIGH" || sev("S02", "D04") != "HIGH" || sev("S03", "D04") != "MEDIUM" || sev("S07", "U10") != "LOW" {
		t.Error("sevFor")
	}
	if hexs("ab") != "6162" {
		t.Error("hexs")
	}
	if !isCtl("C0") || isCtl("D04") || isCtl("nope") {
		t.Error("isCtl")
	}
	if got := keys(map[string]bool{"b": true, "a": true}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("keys %v", got)
	}
	if !slices.Equal(keys(boolMap(map[string]int{"z": 1, "y": 2})), []string{"y", "z"}) || !slices.Equal(keys(boolMap2(map[string]string{"q": "", "p": ""})), []string{"p", "q"}) {
		t.Error("boolMap")
	}
	a, b := "rel/a", ""
	absAll(&a, &b)
	if !filepath.IsAbs(a) || b != "" {
		t.Errorf("absAll: %q %q", a, b)
	}
}

func TestSelectAndBuildJobs(t *testing.T) {
	if len(selectMuts("")) != len(muts) {
		t.Error("an empty selector must select every mutation")
	}
	var ids []string
	for _, m := range selectMuts("R0,,B09") {
		ids = append(ids, m.ID)
	}
	for _, want := range []string{"R01", "R05a", "B09a", "B09b"} {
		if !slices.Contains(ids, want) {
			t.Errorf("selector R0,B09 lacks %s: %v", want, ids)
		}
	}
	if slices.Contains(ids, "B01") || slices.Contains(ids, "R10") {
		t.Errorf("selector R0,B09 over-selects: %v", ids)
	}
	all := buildJobs(selectMuts("C0"), "")
	if len(all) != len(mutByID("C0").Scens) {
		t.Errorf("C0 jobs = %d", len(all))
	}
	only := buildJobs(selectMuts("C0"), "S01,S03,")
	if len(only) != 2 || only[0].sc.ID != "S01" || only[1].sc.ID != "S03" {
		t.Errorf("scenario filter: %+v", only)
	}
}

func recs() []RunRec {
	return []RunRec{
		{SDK: "go", Scen: "S03", Mut: "D04", Applied: "applied", Outcome: "ok", Exp: "R", Viol: []Viol{{"O3", "MEDIUM", "success returned"}}},
		{SDK: "node", Scen: "S03", Mut: "D04", Applied: "applied", Outcome: "err:parse", Exp: "R"},
		{SDK: "go", Scen: "S07", Mut: "S13m", Applied: "applied", Outcome: "err:http", Exp: "E", Notes: []string{"O4r token reflected"}},
		{SDK: "go", Scen: "S01", Mut: "C0", Applied: "applied", Outcome: "err:x", Exp: "A", Notes: []string{"unexpected rejection: err:x boom"}},
		{SDK: "node", Scen: "S01", Mut: "T02", Applied: "n/a", Outcome: "ok", Exp: "E", Notes: []string{"H1 driver_error: x"}},
		{SDK: "node", Scen: "S02", Mut: "R03", Applied: "not-reached", Outcome: "died", Exp: "R", Viol: []Viol{{"O1", "HIGH", "exited"}}},
		{SDK: "go", Scen: "S06", Mut: "B01", Applied: "applied", Outcome: "na", Exp: "E"},
	}
}

func TestReportSummarisesViolationsDisagreementsAndNotes(t *testing.T) {
	rep := report(recs(), "unit", 3*time.Second)
	for _, want := range []string{
		"== hostile report unit (3s, 7 records)",
		"go      runs=4 applied=4 (ok=1 err/other=3) n/a=0 not-reached=0 violations: O3=1",
		"node    runs=3 applied=1 (ok=0 err/other=1) n/a=1 not-reached=1 violations: O1=1",
		"HIGH   O1 R03   node    S02 | exited",
		"MEDIUM O3 D04   go      S03 | success returned",
		"-- O5 ok/err disagreements across SDKs: 1 (scenario, mutation) pairs",
		"D04   S03  exp=R go=ok node=err:parse",
		"-- harness notes, O4r reflections and control rejections: 3",
		"go S07 S13m: O4r token reflected",
		"go S01 C0: unexpected rejection: err:x boom",
		"node S01 T02: H1 driver_error: x",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report lacks %q:\n%s", want, rep)
		}
	}
	if strings.Index(rep, "HIGH   O1") > strings.Index(rep, "MEDIUM O3") {
		t.Error("violations must be listed most severe first")
	}
	// more than 60 notes are cut off with an ellipsis
	var many []RunRec
	for range 70 {
		many = append(many, RunRec{SDK: "go", Scen: "S01", Mut: "C0", Applied: "applied", Outcome: "ok", Notes: []string{"H2 note"}})
	}
	if rep := report(many, "many", 0); !strings.Contains(rep, "...\n") || !strings.Contains(rep, ": 70\n") {
		t.Errorf("long note list not cut:\n%s", rep[max(0, len(rep)-200):])
	}
}

func TestResultsRoundTripAndDiff(t *testing.T) {
	base, run := t.TempDir(), t.TempDir()
	cfgA, cfgB := &hostileCfg{out: filepath.Join(base, "out")}, &hostileCfg{out: filepath.Join(run, "out")}
	a := recs()
	b := recs()
	b[0].Viol = nil                                                                                                            // gone: go S03 D04 O3
	b[1].Viol = []Viol{{"O3", "MEDIUM", "new one"}}                                                                            // new for node
	b = append(b, RunRec{SDK: "go", Scen: "S09", Mut: "U09", Applied: "applied", Viol: []Viol{{"O3", "HIGH", "newly wrong"}}}) // new for go
	if err := writeResults(cfgA, a); err != nil {
		t.Fatal(err)
	}
	if err := writeResults(cfgB, b); err != nil {
		t.Fatal(err)
	}
	got, err := loadResults(cfgA.out)
	if err != nil || len(got) != len(a) {
		t.Fatalf("loadResults = %d records, %v", len(got), err)
	}
	if got[0].SDK != "go" || got[0].Mut != "B01" {
		t.Errorf("records are not sorted by sdk, mutation, scenario: first is %s %s", got[0].SDK, got[0].Mut)
	}
	// a corrupt line is skipped, not fatal
	f, _ := os.OpenFile(filepath.Join(cfgA.out, "results.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("not json\n")
	_ = f.Close()
	if again, err := loadResults(cfgA.out); err != nil || len(again) != len(a) {
		t.Errorf("a corrupt line changed the record count: %d, %v", len(again), err)
	}
	if _, err := loadResults(filepath.Join(base, "missing")); err == nil {
		t.Error("loading a missing results dir must fail")
	}
	out := captureStdout(t, func() {
		if err := hostileDiff([]string{"-base", cfgA.out, "-run", cfgB.out, "-sdk", "go"}); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"NEW go S09 U09 O3: newly wrong", "GONE go S03 D04 O3", "new=1 gone=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output lacks %q:\n%s", want, out)
		}
	}
	if err := hostileDiff([]string{"-base", filepath.Join(base, "nope"), "-run", cfgB.out}); err == nil {
		t.Error("diff with a missing baseline must fail")
	}
	if err := hostileDiff([]string{"-base", cfgA.out, "-run", filepath.Join(base, "nope")}); err == nil {
		t.Error("diff with a missing run must fail")
	}
	// the output dir cannot be created under a file
	blocker := filepath.Join(base, "blocker")
	_ = os.WriteFile(blocker, nil, 0o600)
	if err := writeResults(&hostileCfg{out: filepath.Join(blocker, "x")}, a); err == nil {
		t.Error("writeResults under a regular file must fail")
	}
}

func TestSigOfIgnoresOutcomeDetailAndViolationOrder(t *testing.T) {
	r1 := RunRec{Applied: "applied", Outcome: "err:parse", Viol: []Viol{{"O3", "HIGH", "a"}, {"O1", "MEDIUM", "b"}}}
	r2 := RunRec{Applied: "applied", Outcome: "err:http", Viol: []Viol{{"O1", "MEDIUM", "other detail"}, {"O3", "HIGH", "z"}}}
	if sigOf(r1) != sigOf(r2) || sigOf(r1) != "applied|err|O1:MEDIUM,O3:HIGH" {
		t.Errorf("sigs %q %q", sigOf(r1), sigOf(r2))
	}
	if sigOf(RunRec{Applied: "n/a", Outcome: "ok"}) == sigOf(r1) {
		t.Error("different outcomes must differ")
	}
}

func TestCmdHostileDispatch(t *testing.T) {
	if err := cmdHostile(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("no args: %v", err)
	}
	if err := cmdHostile([]string{"bogus"}); err == nil || !strings.Contains(err.Error(), "unknown hostile command") {
		t.Errorf("bogus: %v", err)
	}
	out := captureStdout(t, func() {
		if err := cmdHostile([]string{"list"}); err != nil {
			t.Error(err)
		}
	})
	if n := strings.Count(out, "\n"); n != len(muts) || !strings.Contains(out, "C0    C exp=A") {
		t.Errorf("list printed %d lines for %d mutations:\n%s", n, len(muts), trunc(out, 200))
	}
	if err := cmdHostile([]string{"replay", "-triples", "go:S01"}); err == nil || !strings.Contains(err.Error(), "bad triple") {
		t.Errorf("replay with a bad triple: %v", err)
	}
	if err := cmdHostile([]string{"jsontable", "-corpus", filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Error("jsontable on a missing corpus must fail")
	}
}

func TestJSONTableOverATinyCorpus(t *testing.T) {
	for _, bin := range []string{"python3", "node"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"y_object.json":   `{"a":1}`,
		"y_array.json":    `[1,2]`,
		"n_trailing.json": `{"a":1} x`,
		"n_comma.json":    `[1,]`,
		"i_deep.json":     `[[[[1]]]]`,
		"notes.txt":       `ignored`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := captureStdout(t, func() {
		if err := cmdJSONTable([]string{"-corpus", dir, "-root", "."}); err != nil {
			t.Error(err)
		}
	})
	for _, kind := range []string{"go-decoder", "go-unmarshal", "python", "node"} {
		if !strings.Contains(out, kind) {
			t.Errorf("table lacks %s:\n%s", kind, out)
		}
	}
	// the Go decoder stops after the first value, so it accepts a trailing-garbage document that Unmarshal rejects
	if !strings.Contains(out, "go-decoder    y_ accepted 2/2 | n_ rejected 1/2") || !strings.Contains(out, "go-unmarshal  y_ accepted 2/2 | n_ rejected 2/2") {
		t.Errorf("unexpected Go rows:\n%s", out)
	}
	if !strings.Contains(out, "n_ accepted (1): n_trailing.json") {
		t.Errorf("the Go decoder's trailing-data acceptance is not listed:\n%s", out)
	}
}
