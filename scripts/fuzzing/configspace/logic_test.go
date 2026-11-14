package configspace

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Hermetic tests for the pure parts of the campaign tool: case generation, the
// invariant checks (CheckInProc, CheckProc, CheckPrecedence, CheckAliases) and the
// rendering of a case into a directory. None of them starts a server; the checks are
// driven with hand-built results so each rule is shown to fire and to stay quiet.

const toyModel = `
version: 1
normalisations:
  - {path: a.norm, why: documented}
params:
  - id: p_bad
    path: server.tls.min_version
    group: tls
    values:
      - {v: "1.2", c: valid}
      - {v: bogus, c: invalid}
      - {v: fb, c: invalid, fallback: "defaults to 1.2"}
  - id: p_other
    path: some.other
    group: misc
    values:
      - {v: 1, c: valid, with: {with.key: "$PORT"}}
      - {absent: true, c: absent}
  - id: p_env
    path: KEYORIX_FOO
    kind: env
    group: misc
    values:
      - {v: x, c: valid}
      - {v: y, c: invalid}
      - {absent: true, c: absent}
  - id: p_flag
    path: --flag
    kind: arg
    group: misc
    values:
      - {v: true, c: valid}
      - {absent: true, c: absent}
      - {v: true, c: invalid}
  - id: p_level
    path: --level
    kind: arg
    group: misc
    values:
      - {v: "$PORT2", c: valid}
      - {v: nope, c: invalid, startable: false}
  - id: p_pp
    path: --passphrase-stdin
    kind: arg
    group: misc
    values:
      - {v: true, c: valid}
      - {absent: true, c: absent}
  - id: p_st
    path: storage.type
    group: storage
    values:
      - {v: local, c: valid}
      - {v: postgres, c: valid}
  - id: p_canary
    path: some.secret_token
    group: secrets
    values:
      - {v: "$CANARY:tok", c: valid}
      - {absent: true, c: absent}
conflicts:
  - id: C1
    when: {a.b: ["on"], KEYORIX_FOO: ["$nonempty"]}
    names: [a.b]
  - id: C2
    when: {c.d: ["$absent"]}
    names: [c.d]
    note: process level only
posture:
  - id: P1
    what: insecure thing
    warn: "insecure thing"
    explicit: [x.y]
`

func toy(t testing.TB) *Model {
	t.Helper()
	m, err := ParseModel([]byte(toyModel))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func keysOf(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Inv+"/"+f.Sev+"/"+f.Key)
	}
	sort.Strings(out)
	return out
}

func wantKeys(t *testing.T, got []Finding, want ...string) {
	t.Helper()
	g := keysOf(got)
	sort.Strings(want)
	if !slices.Equal(g, want) {
		t.Fatalf("findings\n got %q\nwant %q", g, want)
	}
}

func TestParseModelRejectsInconsistentModels(t *testing.T) {
	two := "[{v: 1, c: valid}, {v: 2, c: valid}]"
	cases := map[string]string{
		"not yaml":           "params: [",
		"no id":              "params: [{path: a.b, values: " + two + "}]",
		"duplicate id":       "params: [{id: a, path: a.b, values: " + two + "}, {id: a, path: a.c, values: " + two + "}]",
		"duplicate path":     "params: [{id: a, path: a.b, values: " + two + "}, {id: b, path: a.b, values: " + two + "}]",
		"one value":          "params: [{id: a, path: a.b, values: [{v: 1, c: valid}]}]",
		"unknown class":      "params: [{id: a, path: a.b, values: [{v: 1, c: valid}, {v: 2, c: weird}]}]",
		"absent disagrees":   "params: [{id: a, path: a.b, values: [{v: 1, c: valid}, {v: 2, c: absent}]}]",
		"absent without cls": "params: [{id: a, path: a.b, values: [{v: 1, c: valid}, {absent: true, c: valid}]}]",
		"bad posture regexp": "params: []\nposture: [{id: P, warn: \"(\"}]",
	}
	for name, doc := range cases {
		if _, err := ParseModel([]byte(doc)); err == nil {
			t.Errorf("%s: ParseModel accepted an inconsistent model", name)
		}
	}
}

func TestModelAccessors(t *testing.T) {
	m := toy(t)
	if !m.Normalised("a.norm") || m.Normalised("a.other") {
		t.Fatal("Normalised must be true for the listed path only")
	}
	if m.PostureRule("P1") == nil || m.PostureRule("nope") != nil {
		t.Fatal("PostureRule lookup")
	}
	if m.Param("p_bad") == nil || m.Param("nope") != nil {
		t.Fatal("Param lookup")
	}
	cn := m.Counts()
	if cn.Params != 8 || cn.Invalid != 5 || cn.YAML != 4 || cn.Env != 1 || cn.Arg != 3 {
		t.Fatalf("counts = %+v", cn)
	}
	if !slices.Equal(cn.Groups, []string{"misc", "secrets", "storage", "tls"}) {
		t.Fatalf("groups = %v", cn.Groups)
	}
}

func TestSoloCasesCoverEveryValue(t *testing.T) {
	m := mustModel(t)
	solo := SoloCases(m)
	want := 0
	for _, p := range m.Params {
		want += len(p.Values)
	}
	if len(solo) != want {
		t.Fatalf("solo cases = %d, want one per value (%d)", len(solo), want)
	}
	seen := map[string]bool{}
	for _, c := range solo {
		if seen[c.ID] || c.Kind != "solo" || len(c.Assign) != 1 {
			t.Fatalf("bad solo case %+v", c)
		}
		seen[c.ID] = true
	}
}

func TestMutationCasesAreSeededAndBounded(t *testing.T) {
	m := mustModel(t)
	a := MutationCases(m, 25, 7, 3, 9, 0.12)
	b := MutationCases(m, 25, 7, 3, 9, 0.12)
	if len(a) != 25 || len(b) != 25 {
		t.Fatalf("got %d and %d cases", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || fmt.Sprint(a[i].Assign) != fmt.Sprint(b[i].Assign) {
			t.Fatalf("case %d differs between two runs with the same seed", i)
		}
		if n := len(a[i].Assign); n < 3 || n > 9 {
			t.Fatalf("case %s assigns %d options, want 3..9", a[i].ID, n)
		}
		for id, vi := range a[i].Assign {
			if p := m.Param(id); p == nil || vi >= len(p.Values) {
				t.Fatalf("case %s assigns %s=%d outside the model", a[i].ID, id, vi)
			}
		}
	}
	other := MutationCases(m, 25, 8, 3, 9, 0.12)
	same := true
	for i := range a {
		if fmt.Sprint(a[i].Assign) != fmt.Sprint(other[i].Assign) {
			same = false
		}
	}
	if same {
		t.Fatal("a different seed produced the same cases")
	}
}

func TestPairwiseCasesRespectOptions(t *testing.T) {
	m := toy(t)
	all, rows, sizes := PairwiseCases(m, PairwiseOpts{Name: "pair-all", Seed: 1})
	if len(all) == 0 || len(rows) != len(all) || PairGaps(sizes, rows) != 0 {
		t.Fatalf("pair-all: %d cases, %d rows, gaps %d", len(all), len(rows), PairGaps(sizes, rows))
	}
	for _, c := range all {
		for id, vi := range c.Assign {
			if m.Param(id).Values[vi].Class == ClassInvalid {
				t.Fatalf("%s carries the invalid value of %s", c.ID, id)
			}
		}
	}
	start, _, _ := PairwiseCases(m, PairwiseOpts{Name: "pair-start", Seed: 1, StartOnly: true, ExcludeSolo: map[valueKey]bool{{"p_other", 1}: true}})
	for _, c := range start {
		if c.Assign["p_other"] == 1 {
			t.Fatalf("%s carries a value excluded as refused on its own", c.ID)
		}
	}
}

func TestConflictsAndFaultsReadTheRenderedCase(t *testing.T) {
	m := toy(t)
	c := &Case{
		Assign: map[string]int{"p_bad": 1, "p_env": 1, "p_other": 0},
		Doc:    map[string]any{"a": map[string]any{"b": "on"}, "c": map[string]any{"d": 1}},
		Env:    map[string]string{"KEYORIX_FOO": "z"},
		Args:   []string{"--flag", "--level=3"},
	}
	var ids []string
	for _, p := range m.Faults(c) {
		ids = append(ids, p.ID)
	}
	if !slices.Equal(ids, []string{"p_bad", "p_env"}) {
		t.Fatalf("faults = %v", ids)
	}
	var cf []string
	for _, x := range m.TriggeredConflicts(c) {
		cf = append(cf, x.ID)
	}
	if !slices.Equal(cf, []string{"C1"}) { // C2 needs c.d absent
		t.Fatalf("conflicts = %v", cf)
	}
	c.Doc = map[string]any{}
	cf = nil
	for _, x := range m.TriggeredConflicts(c) {
		cf = append(cf, x.ID)
	}
	if !slices.Equal(cf, []string{"C2"}) { // a.b no longer on
		t.Fatalf("conflicts after clearing = %v", cf)
	}
}

func TestLookupAndMatchOne(t *testing.T) {
	c := &Case{
		Doc:  map[string]any{"storage": map[string]any{"dsn": "host=h user=u password=p", "url": "postgres://u:s3@h/db", "plain": "host=h"}},
		Env:  map[string]string{"KEYORIX_X": "v"},
		Args: []string{"--a", "--b=1"},
	}
	for path, want := range map[string]bool{"storage.dsn#haspw": true, "storage.url#haspw": true, "storage.plain#haspw": false, "storage.none#haspw": false} {
		if v, ok := c.lookup(path); !ok || v != want {
			t.Errorf("lookup(%s) = %v, %v; want %v", path, v, ok, want)
		}
	}
	if v, ok := c.lookup("KEYORIX_X"); !ok || v != "v" {
		t.Errorf("env lookup = %v %v", v, ok)
	}
	if _, ok := c.lookup("KEYORIX_NOPE"); ok {
		t.Error("absent env var reported present")
	}
	for _, f := range []string{"--a", "--b"} {
		if v, ok := c.lookup(f); !ok || v != true {
			t.Errorf("flag %s lookup = %v %v", f, v, ok)
		}
	}
	if _, ok := c.lookup("--c"); ok {
		t.Error("absent flag reported present")
	}
	if v, ok := c.lookup("storage.plain"); !ok || v != "host=h" {
		t.Errorf("doc lookup = %v %v", v, ok)
	}
	for _, tc := range []struct {
		want, got any
		present   bool
		out       bool
	}{
		{"$absent", nil, false, true}, {"$absent", "x", true, false},
		{"$empty", "", true, true}, {"$empty", "x", true, false}, {"$empty", nil, false, false},
		{"$nonempty", "x", true, true}, {"$nonempty", "", true, false}, {"$nonempty", nil, false, false},
		{"on", "on", true, true}, {true, "true", true, true}, {"on", "off", true, false}, {"on", nil, false, false},
	} {
		if got := matchOne(tc.want, tc.got, tc.present); got != tc.out {
			t.Errorf("matchOne(%v, %v, %v) = %v, want %v", tc.want, tc.got, tc.present, got, tc.out)
		}
	}
}

func TestPathHelpers(t *testing.T) {
	doc := map[string]any{}
	setPath(doc, "a.b.c", 1, false)
	setPath(doc, "a.b.d", 2, false)
	if v, ok := GetPath(doc, "a.b.c"); !ok || v != 1 {
		t.Fatalf("GetPath after setPath = %v %v", v, ok)
	}
	if _, ok := GetPath(doc, "a.b.c.d"); ok {
		t.Fatal("GetPath walked through a scalar")
	}
	if _, ok := GetPath(doc, "a.x"); ok {
		t.Fatal("GetPath found a missing key")
	}
	cp := deepCopy(doc).(map[string]any)
	setPath(cp, "a.b.c", 9, false)
	setPath(cp, "a.b.d", nil, true)
	setPath(cp, "q.r", nil, true) // deleting below a missing parent is a no-op
	if v, _ := GetPath(doc, "a.b.c"); v != 1 {
		t.Fatal("deepCopy shares storage with the original")
	}
	if _, ok := GetPath(cp, "a.b.d"); ok {
		t.Fatal("setPath delete left the key")
	}
	if _, ok := GetPath(cp, "q"); ok {
		t.Fatal("setPath delete created a parent")
	}
	if got := deepCopy([]any{map[string]any{"k": []any{1}}}).([]any); len(got) != 1 {
		t.Fatalf("deepCopy of a list = %v", got)
	}
}

func TestPostureHelpers(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true, "10.0.0.1": false, "example.com": false, "": false} {
		if got := isLoopbackHost(h); got != want {
			t.Errorf("isLoopbackHost(%q) = %v", h, got)
		}
	}
	for o, want := range map[string]string{
		"https://app.example.com":     "app.example.com",
		"http://localhost:3000/path":  "localhost",
		"https://[::1]:8443":          "::1",
		"app.example.com:8080":        "app.example.com",
		"http://app.example.com/x/y?": "app.example.com",
	} {
		if got := hostOfOrigin(o); got != want {
			t.Errorf("hostOfOrigin(%q) = %q, want %q", o, got, want)
		}
	}
}

func TestSmallStringHelpers(t *testing.T) {
	if got := warnLines("INFO ok\nWARN: a\nlevel=warning b\n"); len(got) != 2 {
		t.Fatalf("warnLines = %q", got)
	}
	if canaryTail("short") != "short" || canaryTail("0123456789abcdef") != "456789abcdef" {
		t.Fatal("canaryTail")
	}
	if tail("abc", 5) != "abc" || tail("0123456789", 4) != "...6789" {
		t.Fatal("tail")
	}
	if !errNames("Refused: SERVER.TLS.min_version is bad", []string{"", "nope", "server.tls.min_version"}) || errNames("x", []string{""}) {
		t.Fatal("errNames")
	}
	if lastSeg("a.b.c") != "c" || lastSeg("c") != "c" {
		t.Fatal("lastSeg")
	}
	if !secGroup("tls") || secGroup("misc") {
		t.Fatal("secGroup")
	}
	if !sameStrings([]string{"b", "a"}, []string{"a", "b"}) || sameStrings([]string{"a"}, []string{"a", "a"}) {
		t.Fatal("sameStrings")
	}
	if refusalSig(strings.Repeat("x", 100)) != strings.Repeat("x", 80) || refusalSig("short") != "short" {
		t.Fatal("refusalSig")
	}
	c := &Case{Assign: map[string]int{"d": 0, "c": 0, "b": 0, "a": 0}}
	if firstAssign(c) != "a+b+c" {
		t.Fatalf("firstAssign = %q", firstAssign(c))
	}
	cp := copyAssign(c.Assign)
	cp["a"] = 5
	if c.Assign["a"] != 0 {
		t.Fatal("copyAssign shares the map")
	}
	for _, tc := range []struct {
		p    Param
		want []string
	}{
		{Param{Path: "cors.allowed_origins", Kind: KindYAML}, []string{"cors.allowed_origins", "allowed_origins", "allowed_origin"}},
		{Param{Path: "server.http.port", Kind: KindYAML}, []string{"server.http.port", "port"}},
		{Param{Path: "--flag", Kind: KindArg}, []string{"--flag", "--flag", "flag"}},
		{Param{Path: "KEYORIX_X", Kind: KindEnv}, []string{"KEYORIX_X", "KEYORIX_X", "KEYORIX_X"}},
	} {
		if got := tokensFor(&tc.p); !slices.Equal(got, tc.want) {
			t.Errorf("tokensFor(%s) = %q, want %q", tc.p.Path, got, tc.want)
		}
	}
}

func TestSameValue(t *testing.T) {
	for _, tc := range []struct {
		written, eff any
		want         bool
	}{
		{[]any{"a", "b"}, []string{"a", "b"}, true},
		{[]any{"a"}, []string{"a", "b"}, false},
		{[]any{"a", "c"}, []string{"a", "b"}, false},
		{nil, []string{}, true},
		{"x", []string{}, false},
		{nil, nil, true},
		{"x", nil, false},
		{5, 5, true},
		{"5", 5, true},
		{"5", 6, false},
	} {
		if got := sameValue(tc.written, tc.eff); got != tc.want {
			t.Errorf("sameValue(%#v, %#v) = %v", tc.written, tc.eff, got)
		}
	}
}

func TestLookupEffective(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.AllowedOrigins = []string{"https://a", "https://b"}
	if v, ok := lookupEffective(cfg, "storage.type"); !ok || v != "local" {
		t.Fatalf("string leaf = %v %v", v, ok)
	}
	if v, ok := lookupEffective(cfg, "server.http.enabled"); !ok || v != true {
		t.Fatalf("bool leaf = %v %v", v, ok)
	}
	if v, ok := lookupEffective(cfg, "server.http.allowed_origins"); !ok || !slices.Equal(v.([]string), []string{"https://a", "https://b"}) {
		t.Fatalf("slice leaf = %v %v", v, ok)
	}
	for _, p := range []string{"no.such.path", "storage", "storage.type.deeper"} {
		if _, ok := lookupEffective(cfg, p); ok {
			t.Errorf("lookupEffective(%q) resolved", p)
		}
	}
}

func TestCheckInProc(t *testing.T) {
	m := toy(t)
	base := func(assign map[string]int) *Case {
		return &Case{ID: "t", Kind: "solo", Assign: assign, Doc: map[string]any{"c": map[string]any{"d": 1}}, Env: map[string]string{}}
	}

	t.Run("panic stops the rest", func(t *testing.T) {
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_bad": 1}), InProcResult{Panic: "boom"}), "I1/S3/panic:solo:p_bad")
	})
	t.Run("canary in the error text", func(t *testing.T) {
		c := base(map[string]int{"p_other": 0})
		c.Canaries = map[string]string{"cnry_tok_1": "tok"}
		wantKeys(t, CheckInProc(m, c, InProcResult{Err: "bad value cnry_tok_1"}), "I4/S1/leak-err:tok")
	})
	t.Run("single invalid value accepted", func(t *testing.T) {
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_bad": 1}), InProcResult{Accepted: true}),
			"I2/S2/invalid-accepted:p_bad:bogus") // tls is a security group
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_bad": 2}), InProcResult{Accepted: true}),
			"I2/S2/invalid-fallback:p_bad:fb")
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_env": 1}), InProcResult{Accepted: true}),
			"I2/S3/invalid-accepted:p_env:y")
	})
	t.Run("arguments are judged by the process stage", func(t *testing.T) {
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_flag": 2}), InProcResult{Accepted: true}))
	})
	t.Run("several faults may mask each other", func(t *testing.T) {
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_bad": 1, "p_env": 1}), InProcResult{Accepted: true}))
	})
	t.Run("a live conflict accepted", func(t *testing.T) {
		c := base(nil)
		c.Doc = map[string]any{"a": map[string]any{"b": "on"}, "c": map[string]any{"d": 1}}
		c.Env = map[string]string{"KEYORIX_FOO": "z"}
		wantKeys(t, CheckInProc(m, c, InProcResult{Accepted: true}), "I2/S2/conflict-accepted:C1")
	})
	t.Run("posture reached without an explicit key", func(t *testing.T) {
		c := base(nil)
		wantKeys(t, CheckInProc(m, c, InProcResult{Accepted: true, Posture: []string{"P1"}}), "I3/S2/posture-default:P1")
		c.Doc["x"] = map[string]any{"y": true}
		wantKeys(t, CheckInProc(m, c, InProcResult{Accepted: true, Posture: []string{"P1"}}))
		// C2 is refused by the boot, so its posture is never reached
		wantKeys(t, CheckInProc(m, &Case{ID: "t", Assign: map[string]int{}, Doc: map[string]any{}}, InProcResult{Accepted: true, Posture: []string{"P1"}}))
	})
	t.Run("a written value that differs from the effective one", func(t *testing.T) {
		c := base(map[string]int{"p_st": 1})
		c.Doc["storage"] = map[string]any{"type": "postgres"}
		cfg := &config.Config{}
		cfg.Storage.Type = "local"
		wantKeys(t, CheckInProc(m, c, InProcResult{Accepted: true, Cfg: cfg}), "I3/S3/fidelity:p_st:postgres")
		cfg.Storage.Type = "postgres"
		wantKeys(t, CheckInProc(m, c, InProcResult{Accepted: true, Cfg: cfg}))
	})
	t.Run("refusal names the option or not", func(t *testing.T) {
		c := base(map[string]int{"p_bad": 1})
		wantKeys(t, CheckInProc(m, c, InProcResult{Err: "boom"}), "I2/S3/refusal-unnamed:p_bad")
		wantKeys(t, CheckInProc(m, c, InProcResult{Err: "server.tls.min_version is not valid"}))
		// no known fault and no live conflict: nothing to name
		wantKeys(t, CheckInProc(m, base(map[string]int{"p_other": 0}), InProcResult{Err: "boom"}))
	})
}

func TestCheckProc(t *testing.T) {
	m := toy(t)
	mk := func(assign map[string]int, doc map[string]any) *Case {
		if doc == nil {
			doc = map[string]any{"c": map[string]any{"d": 1}}
		}
		return &Case{ID: "t", Kind: "solo", Assign: assign, Doc: doc, Env: map[string]string{}, Canaries: map[string]string{}}
	}
	healthy := func() ProcResult {
		return ProcResult{Started: true, ShutdownOK: true, Graceful: true, Health: map[string]int{"http://127.0.0.1:8080": 200}}
	}
	ok := InProcResult{Accepted: true}

	t.Run("a healthy start is quiet", func(t *testing.T) {
		wantKeys(t, CheckProc(m, mk(map[string]int{}, nil), ok, healthy()))
	})
	t.Run("crash and hang", func(t *testing.T) {
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_other": 0}, nil), ok, ProcResult{Started: true, Signal: "segmentation fault"}),
			"I1/S2/proc-crash:p_other", "I6/S3/shutdown:p_other")
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_other": 0}, nil), ok, ProcResult{Log: "goroutine\npanic: boom"}),
			"I1/S3/proc-crash:p_other", "I2/S3/refusal-exit0:p_other", "I2/S4/boot-refusal:p_other")
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_other": 0}, nil), ok, ProcResult{TimedOut: true}),
			"I1/S3/proc-hang:p_other")
	})
	t.Run("canaries leaked through every surface", func(t *testing.T) {
		c := mk(map[string]int{}, nil)
		c.Canaries["cnry_tok_0123456789ab"] = "tok"
		pr := ProcResult{Exit: 1, Log: "x cnry_tok_0123456789ab", Bodies: map[string]string{"http://h:1/metrics": "200 cnry_tok_0123456789ab"},
			Admin: map[string]string{"admin diagnose": "cnry_tok_0123456789ab"}}
		wantKeys(t, CheckProc(m, c, InProcResult{}, pr),
			"I4/S1/leak:tok:log", "I4/S1/leak:tok:http /metrics", "I4/S1/leak:tok:admin admin diagnose")
	})
	t.Run("refusals", func(t *testing.T) {
		// refused with exit 0, naming nothing
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_bad": 1}, nil), InProcResult{}, ProcResult{Log: "no idea"}),
			"I2/S3/refusal-exit0:p_bad", "I2/S3/proc-refusal-unnamed:p_bad")
		// refused properly, naming the option
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_bad": 1}, nil), InProcResult{}, ProcResult{Exit: 1, Log: "server.tls.min_version is invalid"}))
		// a refusal the in-process check did not predict
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_other": 0}, nil), ok, ProcResult{Exit: 1, Log: "late refusal"}), "I2/S4/boot-refusal:p_other")
		// a conflict names its own tokens
		wantKeys(t, CheckProc(m, mk(map[string]int{}, map[string]any{}), InProcResult{}, ProcResult{Exit: 1, Log: "c.d is required"}))
	})
	t.Run("started although a rule refuses", func(t *testing.T) {
		c := mk(map[string]int{"p_other": 0}, nil)
		wantKeys(t, CheckProc(m, c, InProcResult{Err: "bad"}, healthy()), "I2/S2/started-but-validate-refused:p_other")
		wantKeys(t, CheckProc(m, c, InProcResult{LoadFailed: true, Err: "bad"}, healthy()), "I2/S2/started-but-load-failed:p_other")
		wantKeys(t, CheckProc(m, mk(map[string]int{}, map[string]any{}), ok, healthy()), "I2/S2/proc-conflict-started:C2")
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_bad": 1}, nil), ok, healthy()), "I2/S2/proc-invalid-started:p_bad:bogus")
		wantKeys(t, CheckProc(m, mk(map[string]int{"p_bad": 2}, nil), ok, healthy())) // documented fallback
	})
	t.Run("health and shutdown", func(t *testing.T) {
		pr := healthy()
		pr.Health = map[string]int{"http://127.0.0.1:8080": 503}
		pr.ShutdownOK, pr.Exit = false, 2
		wantKeys(t, CheckProc(m, mk(map[string]int{}, nil), ok, pr), "I6/S3/health:", "I6/S3/shutdown:")
		pr = healthy()
		pr.Graceful = false
		wantKeys(t, CheckProc(m, mk(map[string]int{}, nil), ok, pr), "I6/S4/shutdown-line:")
	})
	t.Run("posture must be warned about", func(t *testing.T) {
		in := InProcResult{Accepted: true, Posture: []string{"P1"}}
		pr := healthy()
		wantKeys(t, CheckProc(m, mk(map[string]int{}, nil), in, pr), "I3/S1/no-warning:P1")
		explicit := mk(map[string]int{}, map[string]any{"c": map[string]any{"d": 1}, "x": map[string]any{"y": true}})
		wantKeys(t, CheckProc(m, explicit, in, pr), "I3/S2/no-warning:P1")
		pr.Log = "level=WARN msg=\"insecure thing in effect\""
		wantKeys(t, CheckProc(m, mk(map[string]int{}, nil), in, pr))
	})
}

func TestPrecedenceCases(t *testing.T) {
	cs := PrecedenceCases()
	ids := map[string]bool{}
	for _, c := range cs {
		if ids[c.ID] || c.Kind != "targeted" || (len(c.RawEnv) == 0 && len(c.RawYAML) == 0) {
			t.Fatalf("bad targeted case %+v", c)
		}
		ids[c.ID] = true
	}
	for _, a := range accessors {
		if !ids["prec-envwins-"+a.Env] {
			t.Errorf("no env-wins case for %s", a.Env)
		}
	}
	if !ids["prec-dsnpw-env"] || ids["prec-both-KEYORIX_MASTER_PASSWORD"] {
		t.Error("dsn case missing or master password not excluded")
	}
	for _, n := range config.SecretEnvVars {
		if n == "KEYORIX_MASTER_PASSWORD" {
			continue
		}
		for _, k := range []string{"both", "badfile", "emptyfile", "dirfile"} {
			if !ids["prec-"+k+"-"+n] {
				t.Errorf("no %s case for %s", k, n)
			}
		}
	}
}

func TestCheckPrecedence(t *testing.T) {
	n := "KEYORIX_SIEM_TOKEN"
	for _, k := range []string{"both", "badfile", "emptyfile", "dirfile"} {
		c := &Case{ID: "prec-" + k + "-" + n}
		wantKeys(t, CheckPrecedence(c, InProcResult{Panic: "boom"}), "I5/S3/prec-panic:"+c.ID)
		wantKeys(t, CheckPrecedence(c, InProcResult{Accepted: true}), "I5/S2/prec-accepted:"+c.ID)
		wantKeys(t, CheckPrecedence(c, InProcResult{Err: "refused"}), "I5/S3/prec-unnamed:"+c.ID)
		wantKeys(t, CheckPrecedence(c, InProcResult{Err: "refused: " + n + "_FILE unreadable"}))
	}
	win := &Case{ID: "prec-envwins-" + n, Canaries: map[string]string{"cnry_env": "envvalue", "cnry_yaml": "yamlvalue"}}
	wantKeys(t, CheckPrecedence(win, InProcResult{}))
	cfg := &config.Config{}
	wantKeys(t, CheckPrecedence(win, InProcResult{Cfg: cfg, Acc: map[string]string{n: "cnry_env"}}))
	wantKeys(t, CheckPrecedence(win, InProcResult{Cfg: cfg, Acc: map[string]string{n: "cnry_yaml"}}), "I5/S2/prec-envloses:"+n)
	dsn := &Case{ID: "prec-dsnpw-env"}
	wantKeys(t, CheckPrecedence(dsn, InProcResult{Accepted: true}), "I5/S2/prec-dsnpw-accepted")
	wantKeys(t, CheckPrecedence(dsn, InProcResult{Err: "refused"}))
	wantKeys(t, CheckPrecedence(&Case{ID: "something-else"}, InProcResult{Accepted: true}))
}

func TestAliasYAML(t *testing.T) {
	if got := aliasYAML("a.b", true); fmt.Sprint(got) != "map[a.b:true]" {
		t.Fatalf("plain path = %v", got)
	}
	got := aliasYAML("x.list[].enabled", true)
	el := got["x.list"].([]any)[0].(map[string]any)
	if el["enabled"] != true || el["name"] != "csprov" {
		t.Fatalf("list element = %v", got)
	}
	got = aliasYAML("x.list[].a.b", 7)
	el = got["x.list"].([]any)[0].(map[string]any)
	if el["a"].(map[string]any)["b"] != 7 {
		t.Fatalf("nested list element = %v", got)
	}
	got = aliasYAML("x.list[]", nil)
	if el = got["x.list"].([]any)[0].(map[string]any); len(el) != 1 || el["name"] != "csprov" {
		t.Fatalf("bare list element = %v", got)
	}
}

func TestAliasCasesFollowTheCodesAliasTable(t *testing.T) {
	pairs := config.DeprecatedSettingAliasPaths()
	if len(pairs) == 0 {
		t.Fatal("the code declares no deprecated aliases: the alias checks would be vacuous")
	}
	cs := AliasCases()
	if len(cs) != 1+4*len(pairs) || cs[0].ID != "alias-base" {
		t.Fatalf("%d alias cases for %d aliases", len(cs), len(pairs))
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if seen[c.ID] {
			t.Fatalf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestCheckAliases(t *testing.T) {
	pairs := config.DeprecatedSettingAliasPaths()
	if len(pairs) == 0 {
		t.Fatal("no aliases")
	}
	quiet := func() map[string]InProcResult {
		res := map[string]InProcResult{"alias-base": {Accepted: true}}
		for i := range pairs {
			for _, tag := range []string{"old", "new", "oldT-newF", "oldF-newT"} {
				res[fmt.Sprintf("alias-%02d-%s", i, tag)] = InProcResult{Accepted: true, Warnings: []string{"deprecated"}}
			}
		}
		return res
	}
	id := func(tag string) string { return "alias-00-" + tag }
	old := pairs[0][0]

	if fs := CheckAliases(quiet()); len(fs) != 0 {
		t.Fatalf("a consistent table produced %v", keysOf(fs))
	}
	res := quiet()
	res[id("new")] = InProcResult{Panic: "boom"}
	wantKeys(t, CheckAliases(res), "I5/S3/alias-panic:"+old)

	res = quiet()
	res[id("new")] = InProcResult{LoadFailed: true, Err: "bad"}
	wantKeys(t, CheckAliases(res), "I5/S2/alias-load-diff:"+old)

	res = quiet()
	res[id("old")] = InProcResult{Accepted: true, Warnings: []string{"w"}, Registry: []string{"weak"}}
	wantKeys(t, CheckAliases(res), "I5/S2/alias-effect-diff:"+old)

	res = quiet()
	res[id("old")] = InProcResult{Accepted: true}
	wantKeys(t, CheckAliases(res), "I5/S3/alias-nowarn:"+old)

	res = quiet()
	res[id("oldF-newT")] = InProcResult{Accepted: true, Registry: []string{"weak"}}
	wantKeys(t, CheckAliases(res), "I5/S4/alias-conflict-weaker:"+old)

	res = quiet()
	res[id("oldT-newF")] = InProcResult{Accepted: true, Registry: []string{"weak"}}
	wantKeys(t, CheckAliases(res), "I5/S2/alias-conflict-weaker2:"+old)

	// registry entries already in the baseline are not an effect of the alias
	res = quiet()
	res["alias-base"] = InProcResult{Accepted: true, Registry: []string{"weak"}}
	res[id("oldF-newT")] = InProcResult{Accepted: true, Registry: []string{"weak"}}
	wantKeys(t, CheckAliases(res))
}

// template writes the smallest baseline directory Materialize and LoadTemplate need.
func template(t *testing.T) *Template {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"secrets", "certs", "keys", "db"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("keyorix.yaml", "environment: local\nserver:\n  http:\n    enabled: true\nstorage:\n  type: local\n")
	write("secrets/master_password", "base-pw\n")
	write("certs/server.crt", "not a certificate\n")
	write("db/data.db", "rows")
	if err := os.Symlink(filepath.Join(dir, "db", "data.db"), filepath.Join(dir, "db", "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tpl, err := LoadTemplate(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestLoadTemplate(t *testing.T) {
	tpl := template(t)
	if tpl.Passphrase != "base-pw" {
		t.Fatalf("passphrase = %q", tpl.Passphrase)
	}
	if v, _ := GetPath(tpl.Doc, "storage.type"); v != "local" {
		t.Fatalf("doc = %v", tpl.Doc)
	}
	empty := t.TempDir()
	if _, err := LoadTemplate(empty); err == nil {
		t.Fatal("a directory without keyorix.yaml loaded")
	}
	if err := os.WriteFile(filepath.Join(empty, "keyorix.yaml"), []byte("a: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTemplate(empty); err == nil {
		t.Fatal("invalid yaml loaded")
	}
	if err := os.WriteFile(filepath.Join(empty, "keyorix.yaml"), []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTemplate(empty); err == nil {
		t.Fatal("a template without secrets/master_password loaded")
	}
}

func TestMaterializeRendersTheCase(t *testing.T) {
	m, tpl := toy(t), template(t)
	root := t.TempDir()
	c := &Case{
		ID:      "mat",
		Assign:  map[string]int{"p_other": 0, "p_env": 0, "p_flag": 0, "p_level": 0, "p_pp": 0, "p_bad": 0, "p_canary": 0},
		RawYAML: map[string]any{"raw.del": nil, "raw.pw": "$BASEPW", "raw.file": "$BASEFILE:master_password"},
		RawEnv:  map[string]string{"KEYORIX_RAW": "$FX:token", "KEYORIX_MASTER_PASSWORD_FILE": "\x00"},
	}
	if err := c.Materialize(m, tpl, root, false); err != nil {
		t.Fatal(err)
	}
	port, port2 := fmt.Sprint(c.Ports[0]), fmt.Sprint(c.Ports[1])
	if v, _ := GetPath(c.Doc, "with.key"); v != port {
		t.Errorf("with.key = %v, want the first port %s", v, port)
	}
	if v, _ := GetPath(c.Doc, "some.other"); v != 1 {
		t.Errorf("some.other = %v", v)
	}
	if v, _ := GetPath(c.Doc, "raw.pw"); v != "base-pw" {
		t.Errorf("raw.pw = %v", v)
	}
	if v, _ := GetPath(c.Doc, "raw.file"); v != filepath.Join(c.Dir, "secrets", "master_password") {
		t.Errorf("raw.file = %v", v)
	}
	if c.Env["KEYORIX_FOO"] != "x" {
		t.Errorf("env = %v", c.Env)
	}
	if _, ok := c.Env["KEYORIX_MASTER_PASSWORD_FILE"]; ok {
		t.Error("RawEnv \\x00 did not delete the variable")
	}
	if !strings.HasSuffix(c.Env["KEYORIX_RAW"], filepath.Join("fx", "token")) {
		t.Errorf("KEYORIX_RAW = %q", c.Env["KEYORIX_RAW"])
	}
	for _, want := range []string{"--flag", "--level=" + port2, "--passphrase-stdin"} {
		if !slices.Contains(c.Args, want) {
			t.Errorf("args %v lack %s", c.Args, want)
		}
	}
	if c.Stdin != "base-pw\n" {
		t.Errorf("stdin = %q", c.Stdin)
	}
	if len(c.Canaries) != 1 {
		t.Errorf("canaries = %v", c.Canaries)
	}
	for val, name := range c.Canaries {
		if name != "tok" || val != canaryFor("mat", "tok") {
			t.Errorf("canary %q => %q", val, name)
		}
	}
	if !c.Startable {
		t.Error("a case of startable values is not startable")
	}
	for _, rel := range []string{"keyorix.yaml", "fx/token", "fx/empty", "fx/garbage", "fx/world", "secrets/master_password", "db/data.db"} {
		if _, err := os.Stat(filepath.Join(c.Dir, rel)); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(c.Dir, "db", "link")); err == nil {
		t.Error("a symlink of the template was copied")
	}
	if c.basePW() != "base-pw" {
		t.Errorf("basePW = %q", c.basePW())
	}

	// light copies only certs, keys and secrets
	light := &Case{ID: "light", Assign: map[string]int{"p_level": 1, "p_flag": 1, "p_other": 1, "p_env": 2}}
	if err := light.Materialize(m, tpl, root, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(light.Dir, "db")); err == nil {
		t.Error("light materialisation copied the database")
	}
	if _, err := os.Stat(filepath.Join(light.Dir, "certs", "server.crt")); err != nil {
		t.Errorf("light materialisation lacks certs: %v", err)
	}
	if light.Startable {
		t.Error("an unstartable value left the case startable")
	}
	if _, ok := GetPath(light.Doc, "some.other"); ok {
		t.Error("an absent value was written")
	}

	bad := &Case{ID: "bad", Assign: map[string]int{"nope": 0}}
	if err := bad.Materialize(m, tpl, root, true); err == nil {
		t.Error("an unknown parameter was accepted")
	}
	if err := (&Case{ID: "x"}).Materialize(m, &Template{Dir: filepath.Join(root, "missing")}, root, true); err == nil {
		t.Error("a missing template directory was accepted")
	}
}

func TestRunInProcOnTheMaterialisedBaseline(t *testing.T) {
	m, tpl := toy(t), template(t)
	c := &Case{ID: "inproc", Assign: map[string]int{"p_st": 0}}
	if err := c.Materialize(m, tpl, t.TempDir(), true); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	res := RunInProc(m, c)
	if now, _ := os.Getwd(); now != wd {
		t.Fatalf("RunInProc left the working directory at %s", now)
	}
	if res.Panic != "" {
		t.Fatalf("panic: %s", res.Panic)
	}
	if !res.Accepted && res.Err == "" {
		t.Fatalf("no verdict: %+v", res)
	}
	if res.Accepted && (res.Cfg == nil || res.Acc == nil) {
		t.Fatalf("accepted without the effective configuration: %+v", res)
	}
	gone := &Case{ID: "gone", Dir: filepath.Join(t.TempDir(), "missing"), Env: map[string]string{}}
	if r := RunInProc(m, gone); !strings.HasPrefix(r.Err, "harness: chdir") {
		t.Fatalf("a missing case directory gave %+v", r)
	}
}

func TestApplyEnvRestores(t *testing.T) {
	t.Setenv("KEYORIX_KEEP_ME", "1")
	restore := applyEnv(map[string]string{"KEYORIX_SET_ME": "2"})
	if _, ok := os.LookupEnv("KEYORIX_KEEP_ME"); ok {
		t.Error("a KEYORIX_ variable survived applyEnv")
	}
	if os.Getenv("KEYORIX_SET_ME") != "2" {
		t.Error("the case variable was not set")
	}
	restore()
	if os.Getenv("KEYORIX_KEEP_ME") != "1" {
		t.Error("restore did not bring the variable back")
	}
	if _, ok := os.LookupEnv("KEYORIX_SET_ME"); ok {
		t.Error("restore left the case variable")
	}
}

func TestProcHelpers(t *testing.T) {
	var b lockedBuf
	if _, err := b.Write([]byte("hello")); err != nil || b.String() != "hello" {
		t.Fatalf("lockedBuf = %q %v", b.String(), err)
	}
	c := &Case{Dir: t.TempDir(), Env: map[string]string{"KEYORIX_A": "1"}}
	env := procEnv(c)
	if !slices.Contains(env, "KEYORIX_A=1") || !slices.Contains(env, "HOME="+c.Dir) {
		t.Fatalf("procEnv = %v", env)
	}
	cmd := niceCmd(t.Context(), "/bin/server", c, "admin", "diagnose")
	if cmd.Dir != c.Dir || !slices.Equal(cmd.Args[1:], []string{"-n", "15", "/bin/server", "admin", "diagnose"}) {
		t.Fatalf("niceCmd = %v in %s", cmd.Args, cmd.Dir)
	}
	if code, sig := exitInfo(nil); code != 0 || sig != "" {
		t.Fatal("exitInfo(nil)")
	}
	if code, _ := exitInfo(fmt.Errorf("plain")); code != -1 {
		t.Fatal("exitInfo(non-exit error)")
	}
}
