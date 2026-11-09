package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Offline tests for the pure helpers of the harness: no server, SDK or network.

func TestCanonTime(t *testing.T) {
	if got := canonTime(5, false); got != 5 {
		t.Fatalf("non-string passes through, got %v", got)
	}
	if got := canonTime("not a time", false); got != "not a time" {
		t.Fatalf("non-time string passes through, got %v", got)
	}
	if got := canonTime("2026-01-02T03:04:05+02:00", false); got != "2026-01-02T01:04:05Z" {
		t.Fatalf("time is normalised to UTC, got %v", got)
	}
	if got := canonTime("2026-01-02T03:04:05Z", true); got != "<volatile-time>" {
		t.Fatalf("volatile time is masked, got %v", got)
	}
	if got := canonTime("plain", true); got != "plain" {
		t.Fatalf("volatile only masks real times, got %v", got)
	}
}

func TestErrSummary(t *testing.T) {
	got := errSummary([]view{
		{sdk: "go", ok: true},
		{sdk: "py", class: "http", status: "404"},
	})
	if got != "go=ok py=http/404" {
		t.Fatalf("got %q", got)
	}
	if errSummary(nil) != "" {
		t.Fatal("empty input gives empty summary")
	}
}

func TestPick3AndRandRefDeterministic(t *testing.T) {
	valid := []int{400, 401, 403, 404, 409, 422, 429, 500, 502, 503}
	r := rand.New(rand.NewSource(1))
	for range 200 {
		if !slices.Contains(valid, pick3(r)) {
			t.Fatal("pick3 returned a status outside its list")
		}
	}
	a, b := rand.New(rand.NewSource(7)), rand.New(rand.NewSource(7))
	for range 200 {
		x, y := randRef(a), randRef(b)
		if x != y {
			t.Fatalf("randRef not deterministic: %q vs %q", x, y)
		}
	}
}

func TestGenSink(t *testing.T) {
	scs := genSink()
	if len(scs) != 7*5 {
		t.Fatalf("want 35 scenarios, got %d", len(scs))
	}
	seen := map[string]bool{}
	for _, s := range scs {
		if seen[s.ID] {
			t.Fatalf("duplicate id %s", s.ID)
		}
		seen[s.ID] = true
		if len(s.Steps) != 1 || s.Steps[0].Fault == nil {
			t.Fatalf("%s: want one step with a fault", s.ID)
		}
		f := s.Steps[0].Fault
		if f.Kind != "redirect" || f.Location != "@sink" {
			t.Fatalf("%s: unexpected fault %+v", s.ID, f)
		}
	}
}

func TestScSizeAndStepOf(t *testing.T) {
	small := Scenario{ID: "a", Steps: []Step{{Op: "health"}}}
	big := Scenario{ID: "a", Steps: []Step{{Op: "health"}, {Op: "health"}}}
	if scSize(big) <= scSize(small) {
		t.Fatal("more steps must be larger")
	}
	o := Outcome{Steps: []StepOutcome{{Drv: map[string]any{"k": 1}}}}
	if stepOf(o, 0).Drv == nil {
		t.Fatal("in-range step must be returned")
	}
	if got := stepOf(o, 3); got.Drv != nil || got.Reqs != nil {
		t.Fatal("out-of-range step must be the zero value")
	}
}

func TestWriteJSONLAndLoadScenarioFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	in := []Scenario{
		{ID: "A-1", Steps: []Step{{Op: "health"}}},
		{ID: "A-2", Tags: []string{"x"}, Steps: []Step{{Op: "login", Args: []Arg{S("u"), Null()}}}},
	}
	if err := writeJSONL(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := readJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].ID != "A-1" || out[1].Steps[0].Args[1].Null != true {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if err := writeJSONL(filepath.Join(dir, "missing", "s.jsonl"), in); err == nil {
		t.Fatal("writing into a missing directory must fail")
	}

	one := filepath.Join(dir, "one.json")
	if err := os.WriteFile(one, []byte(`{"id":"B-1","steps":[{"op":"health"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := loadScenarioFile(one)
	if err != nil || sc.ID != "B-1" || len(sc.Steps) != 1 {
		t.Fatalf("load: %+v %v", sc, err)
	}
	if _, err := loadScenarioFile(filepath.Join(dir, "nope.json")); err == nil {
		t.Fatal("missing file must error")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScenarioFile(bad); err == nil {
		t.Fatal("malformed json must error")
	}
}

func TestShrinkCandidates(t *testing.T) {
	if got := shrinkCandidates(""); len(got) != 1 || got[0] != "" {
		t.Fatalf("empty: %q", got)
	}
	got := shrinkCandidates("abcd")
	for _, want := range []string{"", "ab", "cd", "bcd", "acd", "abd", "abc"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing candidate %q in %q", want, got)
		}
	}
	long := strings.Repeat("é", 60)
	got = shrinkCandidates(long)
	if len(got) != 3 {
		t.Fatalf("long strings only get halves, got %d candidates", len(got))
	}
}

func TestHexArgAndResolveRef(t *testing.T) {
	if hexArg(nil) != "~" {
		t.Fatal("nil arg is ~")
	}
	s := "hi"
	if hexArg(&s) != "6869" {
		t.Fatalf("got %q", hexArg(&s))
	}

	done := []StepOutcome{
		{Drv: map[string]any{"value": map[string]any{"id": "42", "n": float64(0)}}},
		{Drv: map[string]any{"value": []any{map[string]any{"id": "7"}}}},
		{Drv: nil},
		{Drv: map[string]any{"value": "plain"}},
		{Drv: map[string]any{"value": []any{}}},
	}
	cases := []struct {
		ref  Ref
		want string
	}{
		{Ref{Step: 0, Path: "id"}, "42"},
		{Ref{Step: 0, Path: "n"}, "0"},
		{Ref{Step: 0, Path: "absent"}, "0"},
		{Ref{Step: 1, Path: "[0].id"}, "7"},
		{Ref{Step: 1, Path: "[5].id"}, "0"},
		{Ref{Step: 2, Path: "id"}, "0"},
		{Ref{Step: 9, Path: "id"}, "0"},
		{Ref{Step: -1, Path: "id"}, "0"},
		{Ref{Step: 3, Path: "id"}, "0"},
		{Ref{Step: 3, Path: ""}, "plain"},
		{Ref{Step: 4, Path: "[0]"}, "0"},
	}
	for _, c := range cases {
		if got := resolveRef(done, &c.ref); got != c.want {
			t.Errorf("%+v: got %q want %q", c.ref, got, c.want)
		}
	}
}

func TestIDOfAndStrOf(t *testing.T) {
	if idOf(map[string]any{"ID": float64(3)}) != 3 || idOf(map[string]any{"id": float64(4)}) != 4 {
		t.Fatal("both key spellings must resolve")
	}
	if idOf(map[string]any{"id": "x"}) != 0 || idOf(nil) != 0 {
		t.Fatal("non-numeric or absent id is 0")
	}
	m := map[string]any{"b": "two", "c": 3}
	if strOf(m, "a", "b") != "two" {
		t.Fatal("first present string key wins")
	}
	if strOf(m, "c", "z") != "" {
		t.Fatal("non-string values are skipped")
	}
}

func TestBaseEnv(t *testing.T) {
	t.Setenv("TMPDIR", "")
	env := baseEnv("/data")
	if env[0] != "HOME=/data" {
		t.Fatalf("HOME must be the data dir, got %v", env)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "TMPDIR=") {
			t.Fatal("empty TMPDIR must not be forwarded")
		}
	}
	t.Setenv("TMPDIR", "/scratch")
	if !slices.Contains(baseEnv("/data"), "TMPDIR=/scratch") {
		t.Fatal("TMPDIR must be forwarded when set")
	}
}
