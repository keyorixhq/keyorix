package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// More offline tests: spec matching, shape classifiers, masking and tiny file helpers.

const testSpecYAML = `
paths:
  /api/v1/projects:
    get:
      parameters:
        - $ref: '#/components/parameters/Limit'
    post: {}
  /api/v1/projects/{id}:
    parameters:
      - name: expand
        in: query
    get:
      parameters:
        - name: verbose
          in: query
        - name: pid
          in: path
        - "junk"
    trace: {}
  /api/v1/projects/mine:
    get: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
`

func writeSpec(t *testing.T) *Spec {
	t.Helper()
	p := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(p, []byte(testSpecYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSpecCheck(t *testing.T) {
	s := writeSpec(t)
	if _, ok := s.ops["/api/v1/projects/{id}"]["TRACE"]; ok {
		t.Fatal("non-HTTP-method keys must be ignored (TRACE is not indexed)")
	}
	cases := []struct {
		method, uri, want string
	}{
		{"GET", "/api/v1/projects", ""},
		{"GET", "/api/v1/projects?limit=5", ""},
		{"get", "/api/v1/projects/7?expand=1&verbose=2", ""},
		{"GET", "/api/v1/projects/mine", ""},
		{"GET", "/api/v1/projects/%6Dine", ""},
		{"GET", "/api/v1/nothing", "undeclared-path"},
		{"GET", "/api/v1/projects/", ""},
		{"DELETE", "/api/v1/projects", "undeclared-method DELETE /api/v1/projects"},
		{"GET", "/api/v1/projects?bad=1&alpha=2", "undeclared-query GET /api/v1/projects alpha,bad"},
		{"GET", "/api/v1/projects?x=%zz", "unparsable-query /api/v1/projects"},
		{"GET", "/api/v1/projects/%zz", ""},
	}
	for _, c := range cases {
		if got := s.Check(c.method, c.uri); got != c.want {
			t.Errorf("%s %s: got %q want %q", c.method, c.uri, got, c.want)
		}
	}
	// a literal segment must not match an empty one
	if _, ok := s.match("/api/v1//7"); ok {
		t.Error("empty segment must not match a literal template segment")
	}
	// the template with fewer parameters wins
	if got, _ := s.match("/api/v1/projects/mine"); got != "/api/v1/projects/mine" {
		t.Errorf("most specific template must win, got %q", got)
	}
}

func TestLoadSpecErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadSpec(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file must error")
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("paths: [unterminated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSpec(bad); err == nil {
		t.Fatal("malformed yaml must error")
	}
}

func TestPathShape(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"GET /a/b", "GET /a/b/", "trailing-slash"},
		{"GET /a//b", "GET /a/b", "dup-slash"},
		{"GET /a", "GET /b", "path"},
	}
	for _, c := range cases {
		got := pathShape(map[string]string{"x": c.a, "y": c.b})
		if got != c.want {
			t.Errorf("%q vs %q: got %q want %q", c.a, c.b, got, c.want)
		}
	}
	if pathShape(map[string]string{"x": "GET /a"}) != "path" {
		t.Error("a single path is plain path")
	}
}

func TestBodyShape(t *testing.T) {
	got := bodyShape(map[string]string{"x": `true{"a":1,"b":2}`, "y": `true{"a":1,"b":3,"c":4}`})
	if got != "keys=b,c" {
		t.Fatalf("got %q", got)
	}
	if bodyShape(map[string]string{"x": `true{"a":1}`, "y": `falsenot json`}) != "body" {
		t.Fatal("unparsable body falls back to body")
	}
	if bodyShape(map[string]string{"x": `{}`}) != "body" {
		t.Fatal("one body is plain body")
	}
}

func TestFirstDiffPathAndValueShape(t *testing.T) {
	dec := func(s string) any {
		var v any
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		a, b, want string
	}{
		{`[1,2]`, `[1,2]`, ""},
		{`[1,2]`, `[1]`, "$(len)"},
		{`[1]`, `{"a":1}`, "$(type)"},
		{`{"a":1}`, `[1]`, "$(type)"},
		{`{"a":1,"b":[1,2]}`, `{"a":1,"b":[1,3]}`, "$.b[]"},
		{`{"a":1}`, `{"a":2}`, "$.a"},
		{`{"a":1}`, `{"a":1,"z":1}`, "$.z"},
		{`"x"`, `"y"`, "$"},
		{`"x"`, `"x"`, ""},
	}
	for _, c := range cases {
		if got := firstDiffPath(dec(c.a), dec(c.b), "$"); got != c.want {
			t.Errorf("%s vs %s: got %q want %q", c.a, c.b, got, c.want)
		}
	}
	if got := valueShape(map[string]string{"p": `{"a":1}`, "q": `{"a":2}`}); got != "at=$.a" {
		t.Errorf("valueShape: got %q", got)
	}
	if valueShape(map[string]string{"p": `1`}) != "value" {
		t.Error("a single value is plain value")
	}
}

func TestClassShape(t *testing.T) {
	vs := []view{
		{sdk: "a", class: "http", recs: []Rec{{RespStatus: 401}}},
		{sdk: "b", class: "net"},
	}
	if got := classShape(vs); got != "classes=http+net srv=401" {
		t.Errorf("got %q", got)
	}
	vs = []view{{sdk: "a", class: "http", recs: []Rec{{RespStatus: 503}}}}
	if got := classShape(vs); got != "classes=http srv=5xx" {
		t.Errorf("got %q", got)
	}
	if got := classShape([]view{{class: "x", recs: []Rec{{}}}}); got != "classes=x srv=none" {
		t.Errorf("got %q", got)
	}
}

func TestMaskVal(t *testing.T) {
	m := Masking{ProjectMax: 2, EnvMax: 5}
	project := map[string]any{"id": json.Number("9"), "description": "d", "created_at": "2026-01-02T03:04:05Z"}
	got := maskVal(project, m).(map[string]any)
	if got["id"] != "<volatile-id>" || got["created_at"] != "<volatile-time>" {
		t.Fatalf("new project must be masked: %v", got)
	}
	seeded := map[string]any{"id": json.Number("1"), "description": "d", "created_at": "2026-01-02T03:04:05+01:00"}
	got = maskVal(seeded, m).(map[string]any)
	if got["id"] != json.Number("1") || got["created_at"] != "2026-01-02T02:04:05Z" {
		t.Fatalf("seeded project is kept, time normalised: %v", got)
	}
	env := map[string]any{"id": json.Number("8"), "project_id": json.Number("1")}
	if maskVal(env, m).(map[string]any)["id"] != "<volatile-id>" {
		t.Fatal("new environment must be masked")
	}
	secret := map[string]any{"id": json.Number("8"), "project_id": json.Number("1"), "type": "x"}
	if maskVal(secret, m).(map[string]any)["id"] != json.Number("8") {
		t.Fatal("typed rows are not environments")
	}
	list := maskVal([]any{project, "s"}, m).([]any)
	if len(list) != 2 || list[1] != "s" {
		t.Fatalf("lists are masked elementwise: %v", list)
	}
	if canonValue([]any{"a"}, m) != `["a"]` {
		t.Fatal("canonValue renders json")
	}
}

func TestTokenForAndBaseFor(t *testing.T) {
	if tokenFor("", "g") != "g" || tokenFor("good", "g") != "g" || tokenFor("empty", "g") != "" {
		t.Fatal("good/empty tokens")
	}
	if tokenFor("canary", "g") != canaryToken || tokenFor("space", "g") != " "+canaryToken {
		t.Fatal("canary tokens")
	}
	if !strings.Contains(tokenFor("crlf", "g"), "\r\n") || tokenFor("unicode", "g") == "" {
		t.Fatal("crlf/unicode tokens")
	}
	if len(tokenFor("long", "g")) != 65536 {
		t.Fatal("long token length")
	}
	if tokenFor("custom", "g") != "custom" {
		t.Fatal("unknown kinds pass through")
	}

	const a = "127.0.0.1:1"
	want := map[string]string{
		"": "http://" + a, "plain": "http://" + a, "slash": "http://" + a + "/", "slash2": "http://" + a + "//",
		"upper_scheme": "HTTP://" + a, "userinfo": "http://u:p@" + a, "query": "http://" + a + "?x=1",
		"fragment": "http://" + a + "#frag", "prefix": "http://" + a + "/prefix",
		"literal:foo": "foo", "other": "other",
	}
	for kind, w := range want {
		if got := baseFor(kind, a); got != w {
			t.Errorf("baseFor(%q): got %q want %q", kind, got, w)
		}
	}
}

func TestSeedSecretsAndClipStr(t *testing.T) {
	s := seedSecrets()
	if len(s) < 40 || s[len(s)-1].Name != "zz-late" {
		t.Fatalf("unexpected seed set (%d entries)", len(s))
	}
	for _, x := range s {
		if x.Name == "" {
			t.Fatal("seed secret without a name")
		}
	}
	if clipStr("short") != "short" {
		t.Fatal("short strings pass")
	}
	if got := clipStr(strings.Repeat("a", 50)); got != strings.Repeat("a", 40)+"..." {
		t.Fatalf("got %q", got)
	}
}

func TestFindingSig(t *testing.T) {
	f := Finding{Cat: "R1", Op: "health", Blocks: [][]string{{"go", "py"}, {"js"}}, Shape: "at=$"}
	if got := f.Sig(); got != "R1|health|go,py/js|at=$" {
		t.Fatalf("got %q", got)
	}
}

func TestCopyTreeAndFreePort(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"a.txt": "A", "sub/b.txt": "B", "server.log": "skip me"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "sub", "b.txt")); err != nil || string(b) != "B" {
		t.Fatalf("nested file not copied: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "server.log")); err == nil {
		t.Fatal("server.log must not be copied")
	}
	if err := copyTree(filepath.Join(src, "missing"), dst); err == nil {
		t.Fatal("missing source must error")
	}

	p, err := freePort()
	if err != nil || p == "" || p == "0" {
		t.Fatalf("freePort: %q %v", p, err)
	}
}

func TestRandomGeneratorsAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for range 300 {
		_ = randString(r)
		_ = randBase(r)
		_ = randFault(r)
		_ = randArg(r, []string{"a", "b"}, true)
	}
	for seed := range int64(300) {
		a, b := genRandom(seed), genRandom(seed)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			t.Fatalf("seed %d not deterministic", seed)
		}
		if len(a.Steps) == 0 {
			t.Fatalf("seed %d: empty scenario", seed)
		}
	}
}
