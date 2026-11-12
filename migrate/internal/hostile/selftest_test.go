package hostile

// selftest_test.go: harness validity (RULES.md, "Planted defects"). Toy
// clients each carry ONE planted defect plus a correct control. Every defect
// must be caught by its named oracle with a directed program; the control must
// stay silent over the same random program budget. Random detection rates are
// logged, not asserted (they are an honest measure of the fuzzer's reach).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const toyValue = "S3CR3T-VALUE"

type toy func(ctx context.Context, base string) (string, error)

func toyRoutes() []Route {
	return []Route{{Name: "secret", Method: "GET", Prefix: "/secret", Valid: func(int, *http.Request) Resp {
		return Resp{Status: 200, CT: "application/json", Body: []byte(`{"value":"` + toyValue + `","next":""}`)}
	}}}
}

// strict is the oracle's independent decoder: the value and next token iff the
// document is well-formed JSON with a string "value".
func strict(body []byte) (val, next string, ok bool) {
	var d struct {
		Value *string `json:"value"`
		Next  *string `json:"next"`
	}
	if json.Unmarshal(body, &d) != nil || d.Value == nil {
		return "", "", false
	}
	if d.Next != nil {
		next = *d.Next
	}
	return *d.Value, next, true
}

// check is the toy target's oracle set (O5, O6).
func check(h *Harness, val string, err error) {
	if h.Program().Pristine() && (err != nil || val != toyValue) {
		h.Violate("O6 LIVENESS: pristine run returned %q, %v", val, err)
	}
	if err != nil {
		return
	}
	body, ok := h.Intact("secret")
	v, _, valid := strict(body)
	if !ok || !valid || v == "" || v != val {
		h.Violate("O5 FAIL-OPEN: success value %q but delivered intact=%v strict-valid=%v strict-value=%q", val, ok, valid, v)
	}
}

func run(t *testing.T, c toy, p Program, cfg Config) []string {
	t.Helper()
	cfg.Routes, cfg.Program, cfg.RecoverPanics = toyRoutes(), p, true
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 150 * time.Millisecond
	}
	h := New(cfg)
	var val string
	err := h.Run("toy", func(ctx context.Context) error {
		var e error
		val, e = c(ctx, h.URL())
		return e
	})
	check(h, val, err)
	h.Finish(func(string, ...any) {})
	return h.Violations()
}

func fetch(ctx context.Context, cl *http.Client, url string, limit int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	var r io.Reader = resp.Body
	if limit > 0 {
		r = io.LimitReader(resp.Body, limit)
	}
	b, err := io.ReadAll(r)
	return b, resp.StatusCode, err
}

func refuse(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func control(ctx context.Context, base string) (string, error) {
	cl := &http.Client{Timeout: 5 * time.Second, CheckRedirect: refuse}
	seen := map[string]bool{}
	tok := ""
	for range 3 {
		b, code, err := fetch(ctx, cl, base+"/secret"+tok, 1<<20)
		if err != nil || code != 200 {
			return "", fmt.Errorf("fetch failed: status %d: %v", code, err)
		}
		v, next, ok := strict(b)
		if !ok || v == "" {
			return "", fmt.Errorf("no usable value")
		}
		if next == "" {
			return v, nil
		}
		if seen[next] {
			return "", fmt.Errorf("repeated page token")
		}
		seen[next] = true
		tok = "?t=" + next
	}
	return "", fmt.Errorf("too many pages")
}

func p1EmptyOK(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	b, code, err := fetch(ctx, cl, base+"/secret", 1<<20)
	if err != nil || code != 200 {
		return "", fmt.Errorf("fetch failed")
	}
	var d struct{ Value string }
	if json.Unmarshal(b, &d) != nil {
		return "", fmt.Errorf("decode")
	}
	return d.Value, nil // BUG: missing/empty value is success
}

func p2Panic(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	b, code, err := fetch(ctx, cl, base+"/secret", 1<<20)
	if err != nil || code != 200 {
		return "", fmt.Errorf("fetch failed")
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return "", fmt.Errorf("decode")
	}
	return m["value"].(string), nil // BUG: unchecked assertion
}

func p3Unbounded(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	tok := ""
	for { // BUG: no page cap, no repeated-token check
		b, code, err := fetch(ctx, cl, base+"/secret"+tok, 1<<20)
		if err != nil || code != 200 {
			return "", fmt.Errorf("fetch failed")
		}
		v, next, ok := strict(b)
		if !ok {
			return "", fmt.Errorf("decode")
		}
		if next == "" {
			return v, nil
		}
		tok = "?t=" + next
	}
}

func p4Follows(ctx context.Context, base string) (string, error) {
	cl := &http.Client{} // BUG: follows redirects
	b, code, err := fetch(ctx, cl, base+"/secret", 1<<20)
	if err != nil || code != 200 {
		return "", fmt.Errorf("fetch failed")
	}
	v, _, ok := strict(b)
	if !ok || v == "" {
		return "", fmt.Errorf("no value")
	}
	return v, nil
}

func p5EchoSecret(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	b, code, err := fetch(ctx, cl, base+"/secret", 1<<20)
	if err != nil || code != 200 {
		return "", fmt.Errorf("fetch failed")
	}
	v, _, ok := strict(b)
	if !ok || v == "" {
		return "", fmt.Errorf("no value")
	}
	if !strings.HasPrefix(v, "S3") {
		return "", fmt.Errorf("unexpected secret format: %s", v) // BUG: echoes response-controlled value
	}
	return v, nil
}

var valRe = regexp.MustCompile(`"value":"([^"]*)`)

func p6PartialOK(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	b, code, _ := fetch(ctx, cl, base+"/secret", 1<<20) // BUG: read error ignored
	if code != 200 {
		return "", fmt.Errorf("fetch failed")
	}
	m := valRe.FindSubmatch(b)
	if m == nil || len(m[1]) == 0 {
		return "", fmt.Errorf("no value")
	}
	return string(m[1]), nil
}

func p7NoCtx(_ context.Context, base string) (string, error) {
	return control(context.Background(), base) // BUG: ignores the caller's context
}

func p8GoroutineLeak(ctx context.Context, base string) (string, error) {
	v, err := control(ctx, base)
	if err != nil {
		go func() { select {} }() // BUG: leaked on failure
	}
	return v, err
}

func p9Bomb(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	b, code, err := fetch(ctx, cl, base+"/secret", 0) // BUG: unbounded read of a decompressed body
	if err != nil || code != 200 {
		return "", fmt.Errorf("fetch failed")
	}
	v, _, ok := strict(b)
	if !ok {
		return "", fmt.Errorf("decode")
	}
	return v, nil
}

type planted struct {
	id, oracle string
	c          toy
	prog       Program
	cfg        Config
}

var plantedDefects = []planted{
	{"P1 empty-as-success", "O5", p1EmptyOK, Program{Ops: []Op{{1, 1, 0}}}, Config{}},
	{"P2 panic on hostile JSON", "O1", p2Panic, Program{Ops: []Op{{0, 1, 0}}}, Config{}},
	{"P3 unbounded pagination", "O8", p3Unbounded, Program{Occ: 1, Ops: []Op{{6, 2, 14}}}, Config{}},
	{"P4 follows redirect", "O9", p4Follows, Program{Redir: 1}, Config{}},
	{"P5 error echoes canary", "O7", p5EchoSecret, Program{Ops: []Op{{12, 1, 0}}}, Config{}},
	{"P6 partial body accepted", "O5", p6PartialOK, Program{Frame: 1}, Config{}},
	{"P7 ignores context", "O2", p7NoCtx, Program{Fault: 4}, Config{}},
	{"P8 goroutine leak", "O3", p8GoroutineLeak, Program{Status: 10}, Config{}},
	{"P9 unbounded decompression", "O4", p9Bomb, Program{Enc: 2}, Config{CallTimeout: 4 * time.Second}},
}

func TestPlantedDefectsDetectedByDirectedPrograms(t *testing.T) {
	for _, d := range plantedDefects {
		t.Run(d.id, func(t *testing.T) {
			v := run(t, d.c, d.prog, d.cfg)
			for _, m := range v {
				if strings.HasPrefix(m, d.oracle+" ") || strings.HasPrefix(m, d.oracle+"/") {
					return
				}
			}
			t.Fatalf("planted defect %q NOT detected by %s; violations: %v", d.id, d.oracle, v)
		})
	}
}

func TestControlSilentOnDirectedPrograms(t *testing.T) {
	for _, d := range plantedDefects {
		if v := run(t, control, d.prog, d.cfg); len(v) != 0 {
			t.Errorf("control reported violations for %q program %s: %v", d.id, d.prog, v)
		}
	}
	if v := run(t, control, Program{}, Config{}); len(v) != 0 {
		t.Errorf("control not silent on pristine program: %v", v)
	}
}

func randProgram(r *rand.Rand) Program {
	b := make([]byte, 10+3*4)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	for i := range 9 {
		if r.Intn(5) != 0 {
			b[i] = byte(r.Intn(224))
		}
	}
	b[0] = 0
	return Decode(b)
}

func TestRandomBudget(t *testing.T) {
	if os.Getenv("KX_HOSTILE_SELFTEST_RANDOM") == "" {
		t.Skip("random budget is opt-in (KX_HOSTILE_SELFTEST_RANDOM=1; ~5 min): the directed tests above are the gate")
	}
	const n = 500
	r := rand.New(rand.NewSource(20261107))
	progs := make([]Program, n)
	for i := range progs {
		progs[i] = randProgram(r)
	}
	for _, p := range progs {
		if p.Enc == 2 {
			bombBytes()
			break
		}
	}
	cv := 0
	for _, p := range progs {
		if v := run(t, control, p, Config{}); len(v) != 0 {
			cv++
			t.Errorf("control violation for %s: %v", p, v)
		}
	}
	t.Logf("control: %d/%d programs with violations", cv, n)
	for _, d := range plantedDefects {
		if d.id[:2] == "P9" {
			continue // needs a 4s deadline per bomb program; directed test only
		}
		hit := 0
		for _, p := range progs {
			for _, m := range run(t, d.c, p, d.cfg) {
				if strings.HasPrefix(m, d.oracle+" ") || strings.HasPrefix(m, d.oracle+"/") {
					hit++
					break
				}
			}
		}
		t.Logf("random detection %-28s %3d/%d programs", d.id, hit, n)
	}
}

func TestDecodeTotalAndPristine(t *testing.T) {
	if !Decode(nil).Pristine() || !Decode([]byte{}).Pristine() || !Decode(make([]byte, 64)).Pristine() {
		t.Fatal("zero programs must be pristine")
	}
	r := rand.New(rand.NewSource(1))
	for range 2000 {
		b := make([]byte, r.Intn(80))
		r.Read(b)
		p := Decode(b)
		_ = p.MutateBody([]byte(`{"value":"x","next":"","list":[1,2,3],"o":{"a":null}}`))
		_ = p.String()
	}
}
