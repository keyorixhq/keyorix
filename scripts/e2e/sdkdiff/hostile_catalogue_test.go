package main

// Offline checks of the hostile-server mutation catalogue (mutations.go, templates.go): every mutation builds a plan
// for every scenario class it targets, and each plan's body is consistent with the length it declares. No server,
// no SDK driver.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

// capWriter accepts n bytes, then fails like a peer that went away.
type capWriter struct {
	n, wrote int64
}

var errCapped = errors.New("capped")

func (c *capWriter) Write(p []byte) (int, error) {
	if c.wrote+int64(len(p)) > c.n {
		k := max(c.n-c.wrote, 0)
		c.wrote += k
		return int(k), errCapped
	}
	c.wrote += int64(len(p))
	return len(p), nil
}

func catalogueEnv(cls string, gzip bool) *Env {
	return &Env{Cls: cls, Method: "GET", URI: "/x", Path: "/x", Page: 1, AcceptGzip: gzip,
		Hdr: map[string][]string{"authorization": {"Bearer synthetic-token"}}}
}

func TestCatalogueIDsAreUniqueAndScenariosExist(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range muts {
		if seen[m.ID] {
			t.Errorf("duplicate mutation id %s", m.ID)
		}
		seen[m.ID] = true
		if !strings.Contains("RAXE", m.Exp) || m.Exp == "" {
			t.Errorf("%s: expectation %q is not one of R A X E", m.ID, m.Exp)
		}
		if m.Plan == nil {
			t.Errorf("%s: no Plan func", m.ID)
		}
		for _, sid := range m.Scens {
			if scenByID(sid) == nil {
				t.Errorf("%s: unknown scenario %s", m.ID, sid)
			}
		}
		if mutByID(m.ID) != &muts[slices.IndexFunc(muts, func(x Mut) bool { return x.ID == m.ID })] {
			t.Errorf("mutByID(%s) does not return the catalogue entry", m.ID)
		}
	}
	if mutByID("nope") != nil || scenByID("nope") != nil {
		t.Error("lookups of an unknown id must return nil")
	}
	for _, s := range hscens {
		if _, ok := templates[s.Target]; !ok && s.Target != "A" {
			t.Errorf("scenario %s targets class %s without a template", s.ID, s.Target)
		}
	}
}

func TestCatalogueEveryPlanIsConsistent(t *testing.T) {
	const limit = 4 << 20
	built := 0
	for i := range muts {
		m := &muts[i]
		for _, sid := range m.Scens {
			cls := scenByID(sid).Target
			for _, gz := range []bool{false, true} {
				p := m.Plan(catalogueEnv(cls, gz))
				if p == nil {
					continue
				}
				built++
				if p.Body == nil {
					if p.RawResponse == nil && !p.ResetNow && p.BodyLen > 0 {
						t.Errorf("%s/%s: BodyLen %d without a Body", m.ID, sid, p.BodyLen)
					}
					continue
				}
				cw := &capWriter{n: limit}
				var buf bytes.Buffer
				err := p.Body(io.MultiWriter(cw, &buf))
				switch {
				case errors.Is(err, errCapped):
					if p.BodyLen >= 0 && p.BodyLen <= limit {
						t.Errorf("%s/%s: body exceeded %d bytes but declares %d", m.ID, sid, limit, p.BodyLen)
					}
				case err != nil:
					t.Errorf("%s/%s: body: %v", m.ID, sid, err)
				default:
					if p.BodyLen >= 0 && int64(buf.Len()) != p.BodyLen {
						t.Errorf("%s/%s: declares %d body bytes, wrote %d", m.ID, sid, p.BodyLen, buf.Len())
					}
					if m.Ctl && m.ID != "C1" && p.Frame != "chunked" && !json.Valid(buf.Bytes()) {
						t.Errorf("%s/%s: control mutation wrote invalid JSON", m.ID, sid)
					}
				}
			}
		}
	}
	if built < 500 {
		t.Errorf("only %d plans built: the catalogue shrank or a scenario list was emptied", built)
	}
}

func TestCatalogueBodyStopsWhenThePeerGoesAway(t *testing.T) {
	// a writer that fails at once must make every streaming body return that error instead of looping on
	for _, id := range []string{"B01", "B02", "B11", "N03", "G04", "H10"} {
		m := mutByID(id)
		p := m.Plan(catalogueEnv(scenByID(m.Scens[0]).Target, true))
		if p == nil {
			t.Fatalf("%s: no plan", id)
		}
		if err := p.Body(&capWriter{n: 0}); !errors.Is(err, errCapped) {
			t.Errorf("%s: err = %v, want the writer's error", id, err)
		}
	}
	for _, n := range []int64{3, 70 << 10} { // fails inside the filler, then after it
		if err := streamFill([]byte("pre"), []byte("post"), 1<<20, 'A')(&capWriter{n: n}); !errors.Is(err, errCapped) {
			t.Errorf("streamFill capped at %d: err = %v", n, err)
		}
	}
}

func TestCatalogueWantMain(t *testing.T) {
	if got := mutByID("U09").wantMain(); got != "ab\x00cd" {
		t.Errorf("U09 wantMain = %q", got)
	}
	if got := mutByID("U18").wantMain(); len(got) != 1<<20 || got[0] != 'B' {
		t.Errorf("U18 wantMain has %d bytes", len(got))
	}
	if got := mutByID("C0").wantMain(); got != "" {
		t.Errorf("C0 wantMain = %q, want none", got)
	}
}

func TestCatalogueNestTextIsValidJSONAtEveryDepth(t *testing.T) {
	for _, kind := range []string{"arr", "obj", "alt"} {
		for _, depth := range []int{1, 2, 3, 10} {
			o, c := nestText(kind, depth)
			if doc := o + c; kind == "arr" {
				if !json.Valid([]byte(doc)) {
					t.Errorf("%s/%d: %q is not valid JSON", kind, depth, doc)
				}
			} else if doc := `{"x":` + o + c + `}`; !json.Valid([]byte(doc)) {
				t.Errorf("%s/%d: %q is not valid JSON", kind, depth, doc)
			}
		}
	}
}

func TestCatalogueReverseKeys(t *testing.T) {
	in := []byte(`{"a":1,"b":{"c":[1,{"x":true,"y":null}],"d":"s"},"e":1.50}`)
	got := reverseKeys(in)
	want := `{"e":1.50,"b":{"d":"s","c":[1,{"y":null,"x":true}]},"a":1}`
	if string(got) != want {
		t.Errorf("reverseKeys = %s, want %s", got, want)
	}
	if bad := []byte(`{"a":`); !bytes.Equal(reverseKeys(bad), bad) {
		t.Error("an unparsable document must come back unchanged")
	}
}

func TestCatalogueDocHelpers(t *testing.T) {
	e := catalogueEnv("P", false)
	pre, post := splitMain(e)
	if !bytes.Equal(slices.Concat(pre, []byte("alpha"), post), validDoc("P", 1)) {
		t.Error("splitMain around the default main string does not rebuild the document")
	}
	if b := swapMain(e, `{"a":1}`); !json.Valid(b) || bytes.Contains(b, []byte(`"name":"alpha"`)) {
		t.Errorf("swapMain: %s", b)
	}
	if it := firstItem(e, map[string]any{}); it != nil {
		t.Error("firstItem of a document without data must be nil")
	}
	h := catalogueEnv("H", false)
	m := map[string]any{}
	if d := firstItem(h, m); d == nil || m["data"] == nil {
		t.Error("a class without a list must yield (and create) the data object")
	}
	if got := editDoc(e, func(m map[string]any) { delete(m, "data") }); strings.Contains(string(got), "projects") {
		t.Errorf("editDoc kept the removed field: %s", got)
	}
	if p := bigList(h, 3); p != nil {
		t.Error("bigList of a class without a list must be nil")
	}
	var out bytes.Buffer
	p := bigList(e, 3)
	if err := p.Body(&out); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Data struct {
			Projects []json.RawMessage `json:"projects"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("bigList body: %v", err)
	}
	if len(doc.Data.Projects) != 4 { // the 3 repeated items plus the template's second project
		t.Errorf("bigList produced %d items, want 4", len(doc.Data.Projects))
	}
	if p := eofPlan(e, []byte("x")); p.Frame != "eof" || p.BodyLen != -1 {
		t.Errorf("eofPlan frame = %q len = %d", p.Frame, p.BodyLen)
	}
	if trunc("abcdef", 3) != "abc..." || trunc("ab", 3) != "ab" {
		t.Error("trunc")
	}
}

func TestTemplatesUnknownClassIsA404(t *testing.T) {
	if b := renderT("?", "m", "1", "1", 1); !strings.Contains(string(b), "NotFound") {
		t.Errorf("renderT of an unknown class: %s", b)
	}
	p := validPlanFor(catalogueEnv("?", false))
	if p.Status != 404 {
		t.Errorf("unknown class status = %d, want 404", p.Status)
	}
	if b := renderT("L", "n", "7", "3", 0); !strings.Contains(string(b), `"page":1,`) || !strings.Contains(string(b), `"total_pages":3`) {
		t.Errorf("renderT must clamp page to 1 and apply pages: %s", b)
	}
	if ss("a  b\tc")[2] != "c" {
		t.Error("ss")
	}
}
