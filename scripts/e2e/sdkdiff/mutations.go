package main

// Mutation catalogue of the hostile-server mode. Identifiers, expectations and parameters follow hostile/RULES.md
// section 3; a change here that is not in RULES.md must be recorded there as an amendment.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// HScen is one scenario of the hostile-server mode (RULES.md section 2).
type HScen struct {
	ID     string
	Op     string
	Args   []string
	Target string
}

var hscens = []HScen{
	{"S01", "health", nil, "H"},
	{"S02", "login", []string{"synthetic-user", "synthetic-pass"}, "A"},
	{"S03", "list_projects", nil, "P"},
	{"S04", "create_project", []string{"cap1", "d"}, "C"},
	{"S05", "list_environments", []string{"2"}, "E"},
	{"S06", "list_secrets", []string{"production"}, "L"},
	{"S07", "get_secret", []string{"db-password", "production"}, "V"},
	{"S08", "get_secret_by_ref", []string{"alpha/production/db-password"}, "V"},
	{"S09", "get_secret_in", []string{"alpha", "production", "db-password"}, "V"},
	{"S10", "list_deleted_secrets", []string{"2"}, "D"},
	{"S11", "list_secrets", []string{"production"}, "P"},
	{"S12", "list_secrets", []string{"production"}, "E"},
	{"S13", "get_secret", []string{"db-password", "production"}, "L"},
}

func scenByID(id string) *HScen {
	for i := range hscens {
		if hscens[i].ID == id {
			return &hscens[i]
		}
	}
	return nil
}

func ss(s string) []string { return strings.Fields(s) }

var (
	scRep  = ss("S01 S02 S03 S06 S07 S08 S10")
	scBody = ss("S02 S03 S04 S05 S06 S07 S08 S09 S10 S11 S12 S13") // every scenario whose answer is parsed
	scTxt  = ss("S02 S03 S04 S05 S06 S07 S08 S09 S10")
	scNum  = ss("S03 S04 S05 S06 S10 S11 S12 S13")
	scVal  = ss("S07 S08 S09")
	scAll  = ss("S01 S02 S03 S04 S05 S06 S07 S08 S09 S10 S11 S12 S13")
)

// Mut is one mutation.
type Mut struct {
	ID       string
	Family   string
	Desc     string
	Exp      string // R A X E
	Low      bool
	Ctl      bool
	Scens    []string
	Times    int // 0: first request of the target class only, -1: every request of that class
	Plan     func(e *Env) *Plan
	WantMain string // X: decoded main string expected back (V value, list/project name)
	WantID   string // X: decimal id expected back and forwarded; "!" means no success is acceptable
}

var muts []Mut

func add(m Mut) { muts = append(muts, m) }

func mutByID(id string) *Mut {
	for i := range muts {
		if muts[i].ID == id {
			return &muts[i]
		}
	}
	return nil
}

func okPlan(e *Env, b []byte) *Plan { return validPlan(templates[e.Cls].status, b) }

// docWith renders the class document with a replaced main string.
func docWith(e *Env, mainS string) []byte {
	t := templates[e.Cls]
	return renderT(e.Cls, mainS, t.id, "1", e.Page)
}

// swapMain replaces the whole JSON string literal of the main field by repl (arbitrary JSON text).
func swapMain(e *Env, repl string) []byte {
	return bytes.Replace(docWith(e, "@M@"), []byte(`"@M@"`), []byte(repl), 1)
}

// splitMain returns the document text before and after the main string content.
func splitMain(e *Env) (pre, post []byte) {
	d := docWith(e, "@M@")
	pre, post, _ = bytes.Cut(d, []byte("@M@"))
	return pre, post
}

func streamFill(pre, post []byte, n int64, fill byte) func(io.Writer) error {
	return func(w io.Writer) error {
		if _, err := w.Write(pre); err != nil {
			return err
		}
		buf := bytes.Repeat([]byte{fill}, 64<<10)
		for n > 0 {
			k := min(int64(len(buf)), n)
			if _, err := w.Write(buf[:k]); err != nil {
				return err
			}
			n -= k
		}
		_, err := w.Write(post)
		return err
	}
}

func editDoc(e *Env, f func(m map[string]any)) []byte {
	var m map[string]any
	_ = json.Unmarshal(validDoc(e.Cls, e.Page), &m)
	f(m)
	b, _ := json.Marshal(m)
	return b
}

func dataOf(m map[string]any) map[string]any {
	d, _ := m["data"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		m["data"] = d
	}
	return d
}

func firstItem(e *Env, m map[string]any) map[string]any {
	k := templates[e.Cls].list
	if k == "" {
		return dataOf(m)
	}
	l, _ := dataOf(m)[k].([]any)
	if len(l) == 0 {
		return nil
	}
	it, _ := l[0].(map[string]any)
	return it
}

func nestText(kind string, depth int) (open, close string) {
	switch kind {
	case "arr":
		return strings.Repeat("[", depth), strings.Repeat("]", depth)
	case "obj":
		return strings.Repeat(`{"a":`, depth), "1" + strings.Repeat("}", depth)
	}
	// alternating
	var o, c strings.Builder
	for i := range depth {
		if i%2 == 0 {
			o.WriteString(`[`)
		} else {
			o.WriteString(`{"a":`)
		}
	}
	for i := depth - 1; i >= 0; i-- {
		if i%2 == 0 {
			c.WriteString(`]`)
		} else {
			c.WriteString(`}`)
		}
	}
	return o.String(), c.String()
}

// streamNest writes doc with `,"x":<nest>` appended inside the top-level object.
func nestExtra(e *Env, kind string, depth int) *Plan {
	doc := validDoc(e.Cls, e.Page)
	open, closeS := nestText(kind, depth)
	pre := append([]byte(nil), doc[:len(doc)-1]...)
	pre = append(pre, []byte(`,"x":`)...)
	size := int64(len(pre)) + int64(len(open)) + int64(len(closeS)) + 1
	if kind == "obj" {
		size = int64(len(pre)) + int64(len(open)) + int64(len(closeS)) + 1
	}
	p := okPlan(e, nil)
	p.BodyLen = size
	p.Body = func(w io.Writer) error {
		for _, part := range []string{string(pre), open, closeS, "}"} {
			for len(part) > 0 {
				k := min(len(part), 1<<16)
				if _, err := io.WriteString(w, part[:k]); err != nil {
					return err
				}
				part = part[k:]
			}
		}
		return nil
	}
	return p
}

func eofPlan(e *Env, b []byte) *Plan {
	p := okPlan(e, b)
	p.Frame, p.BodyLen = "eof", -1
	return p
}

func reverseKeys(b []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out bytes.Buffer
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch v := t.(type) {
		case json.Delim:
			if v == '[' {
				var items []string
				for dec.More() {
					var sub bytes.Buffer
					save := out
					out = sub
					if err := walk(); err != nil {
						return err
					}
					items = append(items, out.String())
					out = save
				}
				_, _ = dec.Token()
				out.WriteString("[" + strings.Join(items, ",") + "]")
				return nil
			}
			var kvs []string
			for dec.More() {
				kt, _ := dec.Token()
				kb, _ := json.Marshal(kt.(string))
				var sub bytes.Buffer
				save := out
				out = sub
				if err := walk(); err != nil {
					return err
				}
				kvs = append(kvs, string(kb)+":"+out.String())
				out = save
			}
			_, _ = dec.Token()
			for i, j := 0, len(kvs)-1; i < j; i, j = i+1, j-1 {
				kvs[i], kvs[j] = kvs[j], kvs[i]
			}
			out.WriteString("{" + strings.Join(kvs, ",") + "}")
		case json.Number:
			out.WriteString(v.String())
		default:
			jb, _ := json.Marshal(v)
			out.Write(jb)
		}
		return nil
	}
	if walk() != nil {
		return b
	}
	return out.Bytes()
}

// bigList builds the class document with its first list item repeated n times.
func bigList(e *Env, n int) *Plan {
	t := templates[e.Cls]
	if t.list == "" {
		return nil
	}
	doc := validDoc(e.Cls, e.Page)
	k := bytes.Index(doc, []byte(`"`+t.list+`":[`))
	start := k + len(t.list) + 4
	depth, end := 0, -1
	for i := start; i < len(doc); i++ {
		switch doc[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if end > 0 {
			break
		}
	}
	item := doc[start:end]
	pre, post := doc[:end], doc[end:]
	p := okPlan(e, nil)
	p.BodyLen = int64(len(pre)) + int64(n-1)*int64(len(item)+1) + int64(len(post))
	p.Body = func(w io.Writer) error {
		if _, err := w.Write(pre); err != nil {
			return err
		}
		chunk := append([]byte(","), item...)
		var buf bytes.Buffer
		for i := 1; i < n; i++ {
			buf.Write(chunk)
			if buf.Len() > 1<<20 {
				if _, err := w.Write(buf.Bytes()); err != nil {
					return err
				}
				buf.Reset()
			}
		}
		buf.Write(post)
		_, err := w.Write(buf.Bytes())
		return err
	}
	return p
}

func repeatStr(s string, n int) string { return strings.Repeat(s, n) }

func init() {
	// ---- controls ----
	add(Mut{ID: "C0", Family: "C", Desc: "no mutation", Exp: "A", Ctl: true, Scens: scAll,
		Plan: func(e *Env) *Plan { return validPlanFor(e) }})
	add(Mut{ID: "C1", Family: "C", Desc: "pretty-printed JSON", Exp: "A", Ctl: true, Scens: scAll,
		Plan: func(e *Env) *Plan {
			var b bytes.Buffer
			_ = json.Indent(&b, validDoc(e.Cls, e.Page), "", "  ")
			return okPlan(e, b.Bytes())
		}})
	add(Mut{ID: "C2", Family: "C", Desc: "object keys in reverse order", Exp: "A", Ctl: true, Scens: scAll,
		Plan: func(e *Env) *Plan { return okPlan(e, reverseKeys(validDoc(e.Cls, e.Page))) }})
	add(Mut{ID: "C3", Family: "C", Desc: "extra unknown fields", Exp: "A", Ctl: true, Scens: scAll,
		Plan: func(e *Env) *Plan {
			s := string(validDoc(e.Cls, e.Page))
			s = strings.Replace(s, `"data":{`, `"data":{"zz_unknown":{"nested":[1,2,{"k":"v"}]},`, 1)
			s = "{\"zz_top\":1," + s[1:]
			return okPlan(e, []byte(s))
		}})
	add(Mut{ID: "C4", Family: "C", Desc: "Content-Type with charset", Exp: "A", Ctl: true, Scens: scAll,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.CT = "application/json; charset=utf-8"
			return p
		}})

	// ---- nesting ----
	for _, d := range []struct {
		id, kind string
		depth    int
	}{{"N01", "arr", 100}, {"N02", "arr", 10000}, {"N03", "arr", 1000000}, {"N04", "obj", 100}, {"N05", "obj", 10000}, {"N06", "obj", 1000000}, {"N10", "alt", 10000}} {
		kind, depth := d.kind, d.depth
		add(Mut{ID: d.id, Family: "N", Desc: fmt.Sprintf("%s nesting depth %d in an unknown field", kind, depth), Exp: "E", Scens: scBody,
			Plan: func(e *Env) *Plan { return nestExtra(e, kind, depth) }})
	}
	for _, d := range []struct {
		id    string
		depth int
	}{{"N07", 10000}, {"N08", 1000000}} {
		depth := d.depth
		add(Mut{ID: d.id, Family: "N", Desc: fmt.Sprintf("data replaced by an array nested %d deep", depth), Exp: "R", Scens: scBody,
			Plan: func(e *Env) *Plan {
				o, c := nestText("arr", depth)
				return okPlan(e, []byte(`{"success":true,"data":`+o+c+`}`))
			}})
	}
	add(Mut{ID: "N09", Family: "N", Desc: "value/token replaced by a 10000-deep array", Exp: "R", Scens: ss("S02 S07 S08 S09"),
		Plan: func(e *Env) *Plan {
			o, c := nestText("arr", 10000)
			return okPlan(e, swapMain(e, o+c))
		}})

	// ---- bulk and framing ----
	add(Mut{ID: "B01", Family: "B", Desc: "1 GiB string, EOF-framed", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			pre, post := splitMain(e)
			p := okPlan(e, nil)
			p.Frame, p.BodyLen = "eof", -1
			p.Body = streamFill(pre, post, 1<<30, 'A')
			return p
		}})
	add(Mut{ID: "B02", Family: "B", Desc: "100 MiB string, honest Content-Length", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			pre, post := splitMain(e)
			p := okPlan(e, nil)
			p.BodyLen = int64(len(pre)) + 100<<20 + int64(len(post))
			p.Body = streamFill(pre, post, 100<<20, 'A')
			return p
		}})
	add(Mut{ID: "B03", Family: "B", Desc: "Content-Length 100 MiB, short valid body", Exp: "R", Low: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.DeclCL = "decl", []string{strconv.Itoa(100 << 20)}
			return p
		}})
	add(Mut{ID: "B04", Family: "B", Desc: "Content-Length 10 less than the body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.DeclCL = "decl", []string{strconv.Itoa(int(p.BodyLen) - 10)}
			return p
		}})
	add(Mut{ID: "B05", Family: "B", Desc: "Content-Length 1000 more than the body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.DeclCL = "decl", []string{strconv.Itoa(int(p.BodyLen) + 1000)}
			return p
		}})
	add(Mut{ID: "B06", Family: "B", Desc: "no Content-Length, complete body, close", Exp: "A", Ctl: true, Scens: scRep,
		Plan: func(e *Env) *Plan { return eofPlan(e, validDoc(e.Cls, e.Page)) }})
	add(Mut{ID: "B07", Family: "B", Desc: "no Content-Length, body cut at 60%", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			d := validDoc(e.Cls, e.Page)
			return eofPlan(e, d[:len(d)*6/10])
		}})
	add(Mut{ID: "B08", Family: "B", Desc: "two different Content-Length headers", Exp: "R", Low: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.DeclCL = "decl", []string{strconv.Itoa(int(p.BodyLen)), strconv.Itoa(int(p.BodyLen) + 5)}
			return p
		}})
	add(Mut{ID: "B09a", Family: "B", Desc: "Content-Length: -1", Exp: "R", Low: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.DeclCL = "decl", []string{"-1"}
			return p
		}})
	add(Mut{ID: "B09b", Family: "B", Desc: "Content-Length: abc", Exp: "R", Low: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.DeclCL = "decl", []string{"abc"}
			return p
		}})
	add(Mut{ID: "B10", Family: "B", Desc: "Transfer-Encoding chunked and Content-Length", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Frame, p.TEAndCL = "chunked", true
			return p
		}})
	add(Mut{ID: "B11", Family: "B", Desc: "status 500 with a 100 MiB error body, EOF-framed", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			pre := []byte(`{"code":500,"error":"Internal","message":"`)
			p := &Plan{Status: 500, CT: "application/json", Frame: "eof", BodyLen: -1}
			p.Body = streamFill(pre, []byte(`"}`), 100<<20, 'A')
			return p
		}})

	// ---- timing ----
	add(Mut{ID: "T01", Family: "T", Desc: "body dripped at 1 byte per 250 ms", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.After = After{Kind: "drip", N: 0, Dur: 250 * time.Millisecond}
			return p
		}})
	add(Mut{ID: "T02", Family: "T", Desc: "headers, then silence", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.After = After{Kind: "stall", N: 0, Dur: 90 * time.Second}
			return p
		}})
	add(Mut{ID: "T03", Family: "T", Desc: "half of the body, then silence", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.After = After{Kind: "stall", N: p.BodyLen / 2, Dur: 90 * time.Second}
			return p
		}})
	add(Mut{ID: "T04", Family: "T", Desc: "request accepted, no response", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.PreDelay = 90 * time.Second
			return p
		}})
	add(Mut{ID: "T05", Family: "T", Desc: "response head dripped at 1 byte per 100 ms", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.HeadDrip = 100 * time.Millisecond
			return p
		}})

	// ---- reset and truncation ----
	add(Mut{ID: "R01", Family: "R", Desc: "TCP reset after 50% of a declared-length body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.After = After{Kind: "reset", N: p.BodyLen / 2}
			return p
		}})
	add(Mut{ID: "R02", Family: "R", Desc: "clean close after 50% of a declared-length body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.After = After{Kind: "close", N: p.BodyLen / 2}
			return p
		}})
	add(Mut{ID: "R03", Family: "R", Desc: "reset right after the request", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan { return &Plan{ResetNow: true} }})
	add(Mut{ID: "R04", Family: "R", Desc: "close in the middle of the status line", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan { return &Plan{RawResponse: []byte("HTTP/1.1 20")} }})
	for _, c := range []struct {
		id string
		k  func(n int) int
	}{{"R05a", func(n int) int { return 1 }}, {"R05b", func(n int) int { return 10 }}, {"R05c", func(n int) int { return n - 2 }}, {"R05d", func(n int) int { return n - 1 }}} {
		k := c.k
		add(Mut{ID: c.id, Family: "R", Desc: "EOF-framed body cut", Exp: "R", Scens: scRep,
			Plan: func(e *Env) *Plan {
				d := validDoc(e.Cls, e.Page)
				return eofPlan(e, d[:k(len(d))])
			}})
	}
	chunked := func(id, desc, exp string, cs ChunkSpec) {
		add(Mut{ID: id, Family: "R", Desc: desc, Exp: exp, Ctl: exp == "A", Scens: scRep,
			Plan: func(e *Env) *Plan {
				p := validPlanFor(e)
				p.Frame, p.Chunk = "chunked", cs
				return p
			}})
	}
	chunked("R06", "chunked, no terminating chunk, close", "R", ChunkSpec{NoTerm: true})
	chunked("R07", "valid chunked", "A", ChunkSpec{})
	chunked("R08", "valid chunk extensions", "A", ChunkSpec{Ext: ";x=1", Size: 64})
	chunked("R09", "valid trailers", "A", ChunkSpec{Trailers: true})
	chunked("R10", "one-byte chunks", "A", ChunkSpec{Size: 1})
	chunked("R11", "non-hex chunk size", "R", ChunkSpec{BadSize: "zz"})
	chunked("R12", "chunk size 0xFFFFFFFFFFFFFFFFFF", "R", ChunkSpec{BadSize: "FFFFFFFFFFFFFFFFFF"})
	chunked("R13", "chunk size larger than the data, then close", "R", ChunkSpec{OversizeN: 1000})
	chunked("R14", "early zero chunk, more data after", "R", ChunkSpec{Size: 20, EarlyZero: 20})
	chunked("R15", "bare LF chunk lines", "E", ChunkSpec{BareLF: true})
	chunked("R16", "1 MiB chunk extension", "E", ChunkSpec{BigExt: 1 << 20})

	// ---- text ----
	txt := func(id, desc, exp string, low bool, mainText, want string) {
		add(Mut{ID: id, Family: "U", Desc: desc, Exp: exp, Low: low, Scens: scTxt, WantMain: want,
			Plan: func(e *Env) *Plan { return okPlan(e, docWith(e, mainText)) }})
	}
	txt("U01", "raw byte 0xFF in the string", "R", false, "abc\xffdef", "")
	txt("U02", "raw 0xC3 0x28", "R", false, "abc\xc3\x28def", "")
	txt("U03", "overlong C0 AF", "R", false, "abc\xc0\xafdef", "")
	txt("U04", "encoded surrogate ED A0 80", "R", false, "abc\xed\xa0\x80def", "")
	add(Mut{ID: "U05", Family: "U", Desc: "UTF-8 BOM before the document", Exp: "E", Scens: scBody,
		Plan: func(e *Env) *Plan { return okPlan(e, append([]byte("\xef\xbb\xbf"), validDoc(e.Cls, e.Page)...)) }})
	txt("U06", "lone high surrogate escape", "E", false, `ab\ud800cd`, "")
	txt("U07", "lone low surrogate escape", "E", false, `ab\udc00cd`, "")
	txt("U08", "reversed surrogate pair", "E", false, `ab\ude00\ud83dcd`, "")
	txt("U09", "escaped NUL", "X", false, `ab\u0000cd`, "ab\x00cd")
	txt("U10", "raw NUL", "R", true, "ab\x00cd", "")
	txt("U11", "raw CR LF", "R", true, "ab\r\ncd", "")
	txt("U12", "escaped CR LF", "X", false, `ab\r\ncd`, "ab\r\ncd")
	txt("U13", "escapes \\/ \\b \\f \\t \\u00e9", "X", false, `a\/b\b\f\té`, "a/b\b\f\té")
	txt("U14", "escaped surrogate pair", "X", false, `x😀y`, "x\U0001F600y")
	txt("U15", "value ending in a backslash", "X", false, `abc\\`, `abc\`)
	add(Mut{ID: "U16", Family: "U", Desc: "name with escaped quotes and the text value, before the real value", Exp: "X", Scens: scVal, WantMain: "s3cret-value",
		Plan: func(e *Env) *Plan {
			s := strings.Replace(string(validDoc("V", 1)), `"name":"db-password"`, `"name":"a\",\"value\":\"EVIL"`, 1)
			return okPlan(e, []byte(s))
		}})
	add(Mut{ID: "U17", Family: "U", Desc: "nested decoy value key inside secret", Exp: "X", Scens: scVal, WantMain: "s3cret-value",
		Plan: func(e *Env) *Plan {
			s := strings.Replace(string(validDoc("V", 1)), `"secret":{`, `"secret":{"value":"DECOY-VALUE",`, 1)
			return okPlan(e, []byte(s))
		}})
	for _, n := range []struct {
		id  string
		n   int
		exp string
	}{{"U18", 1 << 20, "X"}, {"U19", 16 << 20, "X"}, {"U20", 64 << 20, "E"}} {
		sz, exp := n.n, n.exp
		s := repeatStr("B", sz)
		add(Mut{ID: n.id, Family: "U", Desc: fmt.Sprintf("%d-byte string", sz), Exp: exp, Scens: scTxt, WantMain: s,
			Plan: func(e *Env) *Plan { return okPlan(e, docWith(e, s)) }})
	}
	add(Mut{ID: "U21", Family: "U", Desc: "1 MiB key name", Exp: "E", Scens: scBody,
		Plan: func(e *Env) *Plan {
			d := validDoc(e.Cls, e.Page)
			return okPlan(e, slices.Concat(d[:len(d)-1], []byte(`,"`+repeatStr("k", 1<<20)+`":1}`)))
		}})
	add(Mut{ID: "U22", Family: "U", Desc: "UTF-16LE body with BOM", Exp: "R", Scens: scBody,
		Plan: func(e *Env) *Plan {
			d := validDoc(e.Cls, e.Page)
			out := []byte{0xff, 0xfe}
			for _, c := range d {
				out = append(out, c, 0)
			}
			return okPlan(e, out)
		}})

	// ---- shape and duplicates ----
	dup := func(id string, evilFirst bool) {
		add(Mut{ID: id, Family: "D", Desc: "duplicate main key", Exp: "E", Scens: scBody,
			Plan: func(e *Env) *Plan {
				t := templates[e.Cls]
				orig := `"` + t.key + `":"` + t.main + `"`
				evil := `"` + t.key + `":"EVIL-DUPLICATE"`
				repl := orig + "," + evil
				if evilFirst {
					repl = evil + "," + orig
				}
				return okPlan(e, []byte(strings.Replace(string(validDoc(e.Cls, e.Page)), orig, repl, 1)))
			}})
	}
	dup("D01", false)
	dup("D02", true)
	add(Mut{ID: "D03", Family: "D", Desc: "duplicate data", Exp: "E", Scens: scBody,
		Plan: func(e *Env) *Plan {
			t := templates[e.Cls]
			ev := `{"` + t.key + `":"EVIL-DUPLICATE"}`
			if t.list != "" {
				ev = `{"` + t.list + `":[]}`
			}
			d := validDoc(e.Cls, e.Page)
			return okPlan(e, slices.Concat(d[:len(d)-1], []byte(`,"data":`+ev+`}`)))
		}})
	shape := func(id, desc string, f func(e *Env, m map[string]any)) {
		add(Mut{ID: id, Family: "D", Desc: desc, Exp: "R", Scens: scBody,
			Plan: func(e *Env) *Plan {
				if (id == "D13" || id == "D14") && templates[e.Cls].list == "" {
					return nil
				}
				return okPlan(e, editDoc(e, func(m map[string]any) { f(e, m) }))
			}})
	}
	shape("D04", "data missing", func(e *Env, m map[string]any) { delete(m, "data") })
	shape("D05", "data null", func(e *Env, m map[string]any) { m["data"] = nil })
	shape("D06", "data []", func(e *Env, m map[string]any) { m["data"] = []any{} })
	shape("D07", "data a string", func(e *Env, m map[string]any) { m["data"] = "x" })
	rawMain := func(id, desc, repl string) {
		add(Mut{ID: id, Family: "D", Desc: desc, Exp: "R", Scens: scBody,
			Plan: func(e *Env) *Plan { return okPlan(e, swapMain(e, repl)) }})
	}
	rawMain("D08", "main field a number", "123")
	rawMain("D09", "main field null", "null")
	rawMain("D10", "main field an object", `{"a":1}`)
	rawMain("D11", "main field an array", `["x"]`)
	shape("D12", "main field missing", func(e *Env, m map[string]any) {
		if it := firstItem(e, m); it != nil {
			delete(it, templates[e.Cls].key)
		}
	})
	shape("D13", "list is an object", func(e *Env, m map[string]any) { dataOf(m)[templates[e.Cls].list] = map[string]any{"a": 1} })
	shape("D14", "list items null/number/string", func(e *Env, m map[string]any) {
		dataOf(m)[templates[e.Cls].list] = []any{nil, 1, "x"}
	})
	add(Mut{ID: "D15", Family: "D", Desc: "first list item without name", Exp: "E", Scens: scBody,
		Plan: func(e *Env) *Plan {
			if templates[e.Cls].list == "" {
				return nil
			}
			return okPlan(e, editDoc(e, func(m map[string]any) {
				if it := firstItem(e, m); it != nil {
					delete(it, "name")
				}
			}))
		}})
	raw := func(id, desc string, low bool, exp string, f func(d []byte) []byte) {
		add(Mut{ID: id, Family: "D", Desc: desc, Exp: exp, Low: low, Scens: scBody,
			Plan: func(e *Env) *Plan { return okPlan(e, f(validDoc(e.Cls, e.Page))) }})
	}
	raw("D16", "trailing garbage after the document", true, "R", func(d []byte) []byte { return append(append([]byte{}, d...), []byte(" garbage")...) })
	raw("D17", "two concatenated documents", true, "R", func(d []byte) []byte { return append(append([]byte{}, d...), d...) })
	raw("D18", "empty body", false, "R", func(d []byte) []byte { return []byte{} })
	raw("D19", "whitespace-only body", false, "R", func(d []byte) []byte { return []byte("  \n ") })
	raw("D20", "null", false, "R", func(d []byte) []byte { return []byte("null") })
	raw("D21", "[]", false, "R", func(d []byte) []byte { return []byte("[]") })
	raw("D22", "a string", false, "R", func(d []byte) []byte { return []byte(`"str"`) })
	raw("D23", "a number", false, "R", func(d []byte) []byte { return []byte("123") })
	raw("D24", "{}", false, "R", func(d []byte) []byte { return []byte("{}") })
	raw("D25", "200 with an error envelope", false, "R", func(d []byte) []byte {
		return []byte(`{"code":500,"error":"Internal","message":"boom"}`)
	})
	raw("D26", "200 with success false", false, "R", func(d []byte) []byte { return []byte(`{"success":false,"message":"nope"}`) })
	raw("D27", "comment before the document", true, "R", func(d []byte) []byte { return append([]byte("/* c */ "), d...) })
	raw("D28", "trailing comma", true, "R", func(d []byte) []byte { return append(append([]byte{}, d[:len(d)-1]...), []byte(",}")...) })
	raw("D29", "single-quoted strings", true, "R", func(d []byte) []byte { return bytes.ReplaceAll(d, []byte(`"`), []byte(`'`)) })
	raw("D30", "unquoted keys", true, "R", func(d []byte) []byte {
		out := d
		for _, k := range []string{"success", "data", "token", "value", "secret", "projects", "environments", "secrets", "deleted", "id", "name"} {
			out = bytes.ReplaceAll(out, []byte(`"`+k+`":`), []byte(k+`:`))
		}
		return out
	})

	// ---- status ----
	st := func(id, desc string, status int, exp string, hdr [][2]string) {
		add(Mut{ID: id, Family: "S", Desc: desc, Exp: exp, Scens: scRep,
			Plan: func(e *Env) *Plan {
				p := validPlanFor(e)
				p.Status = status
				p.Headers = hdr
				return p
			}})
	}
	st("S01m", "500 with the success body", 500, "R", nil)
	st("S02m", "404 with the success body", 404, "R", nil)
	st("S03m", "401 with the success body", 401, "R", nil)
	st("S04m", "403 with the success body", 403, "R", nil)
	st("S05m", "302 without Location, success body", 302, "R", nil)
	add(Mut{ID: "S06m", Family: "S", Desc: "204 with empty body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan { return &Plan{Status: 204, Frame: "cl", BodyLen: 0} }})
	st("S07m", "201 where 200 is expected", 201, "E", nil)
	st("S08m", "status 999", 999, "R", nil)
	add(Mut{ID: "S09m", Family: "S", Desc: "status line without reason phrase", Exp: "A", Ctl: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.StatusLine = fmt.Sprintf("HTTP/1.1 %d", p.Status)
			return p
		}})
	add(Mut{ID: "S10m", Family: "S", Desc: "malformed status line", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.StatusLine = "HTTP/1.1 2000 OK"
			return p
		}})
	add(Mut{ID: "S11m", Family: "S", Desc: "no status line", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.NoStatus, p.Frame, p.BodyLen = true, "eof", -1
			return p
		}})
	add(Mut{ID: "S12m", Family: "S", Desc: "100 Continue interim response", Exp: "A", Ctl: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Interim = true
			return p
		}})
	add(Mut{ID: "S13m", Family: "S", Desc: "500 echoing the Authorization header", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			a := ""
			if v := e.Hdr["authorization"]; len(v) > 0 {
				a = v[0]
			}
			b, _ := json.Marshal(map[string]any{"code": 500, "error": "Internal", "message": "request authorization was " + a})
			return validPlan(500, b)
		}})
	add(Mut{ID: "S14m", Family: "S", Desc: "503 with Retry-After: 99999999", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlan(503, []byte(`{"code":503,"error":"Unavailable","message":"later"}`))
			p.Headers = [][2]string{{"Retry-After", "99999999"}}
			return p
		}})
	add(Mut{ID: "S15m", Family: "S", Desc: "HTTP/1.0 response", Exp: "A", Ctl: true, Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.StatusLine = fmt.Sprintf("HTTP/1.0 %d %s", p.Status, reasonFor(p.Status))
			return p
		}})

	// ---- headers and encodings ----
	hd := func(id, desc string, f func(p *Plan)) {
		add(Mut{ID: id, Family: "H", Desc: desc, Exp: "E", Scens: scRep,
			Plan: func(e *Env) *Plan {
				p := validPlanFor(e)
				f(p)
				return p
			}})
	}
	hd("H01", "Content-Type text/html", func(p *Plan) { p.CT = "text/html" })
	hd("H02", "no Content-Type", func(p *Plan) { p.CT = "-" })
	hd("H03", "charset=utf-16 label", func(p *Plan) { p.CT = "application/json; charset=utf-16" })
	hd("H04", "multipart Content-Type", func(p *Plan) { p.CT = "multipart/form-data; boundary=x" })
	hd("H05", "10000 extra headers", func(p *Plan) { p.ExtraHdrs = 10000 })
	hd("H06", "one 1 MiB header line", func(p *Plan) { p.BigHdrBytes = 1 << 20 })
	hd("H07", "header line without colon", func(p *Plan) { p.RawHeaders = []string{"this line has no colon"} })
	hd("H08", "header containing NUL", func(p *Plan) { p.RawHeaders = []string{"X-Nul: a\x00b"} })
	add(Mut{ID: "H09", Family: "H", Desc: "gzip-encoded valid body (R unless advertised)", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			var b bytes.Buffer
			zw := newGzip(&b)
			_, _ = zw.Write(validDoc(e.Cls, e.Page))
			_ = zw.Close()
			p := okPlan(e, b.Bytes())
			p.Gzip = "raw"
			return p
		}})
	add(Mut{ID: "H10", Family: "H", Desc: "gzip bomb, 1 GiB (advertised only)", Exp: "E", Scens: scRep,
		Plan: func(e *Env) *Plan {
			if !e.AcceptGzip {
				return nil
			}
			pre, post := splitMain(e)
			p := okPlan(e, nil)
			p.Frame, p.BodyLen, p.Gzip = "chunked", -1, "ok"
			p.Body = streamFill(pre, post, 1<<30, 'A')
			return p
		}})
	hd("H11", "unknown Content-Encoding", func(p *Plan) { p.Gzip = "foo" })
	add(Mut{ID: "H12", Family: "H", Desc: "Content-Encoding gzip with a plain body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Gzip = "raw"
			return p
		}})
	add(Mut{ID: "H13", Family: "H", Desc: "truncated gzip stream", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			var b bytes.Buffer
			zw := newGzip(&b)
			_, _ = zw.Write(validDoc(e.Cls, e.Page))
			_ = zw.Close()
			g := b.Bytes()
			p := okPlan(e, g[:len(g)-9])
			p.Gzip = "raw"
			return p
		}})
	add(Mut{ID: "H14", Family: "H", Desc: "Content-Encoding br with a plain body", Exp: "R", Scens: scRep,
		Plan: func(e *Env) *Plan {
			p := validPlanFor(e)
			p.Gzip = "br"
			return p
		}})

	// ---- pagination and size ----
	pages := func(id, desc string, f func(e *Env) (string, int)) {
		add(Mut{ID: id, Family: "G", Desc: desc, Exp: "E", Times: -1, Scens: ss("S06 S13"),
			Plan: func(e *Env) *Plan {
				pg, page := f(e)
				t := templates["L"]
				return okPlan(e, renderT("L", t.main, t.id, pg, page))
			}})
	}
	pages("G01", "endless pages", func(e *Env) (string, int) { return strconv.Itoa(e.Page + 1), e.Page })
	pages("G02", "total_pages 2147483647", func(e *Env) (string, int) { return "2147483647", e.Page })
	for i, v := range []string{"1e18", "-1", "0", `"x"`, "null", "1.5"} {
		pages("G03"+string(rune('a'+i)), "total_pages "+v, func(e *Env) (string, int) { return v, e.Page })
	}
	add(Mut{ID: "G04", Family: "G", Desc: "list of 100000 items", Exp: "E", Scens: ss("S03 S05 S06 S10"),
		Plan: func(e *Env) *Plan { return bigList(e, 100000) }})
	add(Mut{ID: "G05", Family: "G", Desc: "list of 1000000 items", Exp: "E", Scens: ss("S03 S06 S10"),
		Plan: func(e *Env) *Plan { return bigList(e, 1000000) }})
	add(Mut{ID: "G06", Family: "G", Desc: "deleted list of 100000 items", Exp: "E", Scens: ss("S10"),
		Plan: func(e *Env) *Plan { return bigList(e, 100000) }})

	// ---- numbers ----
	num := func(id, exp string, low bool, idText, want string) {
		add(Mut{ID: id, Family: "I", Desc: "id " + trunc(idText, 24), Exp: exp, Low: low, Scens: scNum, WantID: want,
			Plan: func(e *Env) *Plan {
				t := templates[e.Cls]
				if t.id == "" {
					return nil
				}
				return okPlan(e, renderT(e.Cls, t.main, idText, "1", e.Page))
			}})
	}
	num("I01", "X", false, "9007199254740993", "9007199254740993")
	num("I02", "X", false, "9223372036854775807", "9223372036854775807")
	num("I03", "X", false, "9223372036854775808", "9223372036854775808")
	num("I04", "X", false, "18446744073709551616", "18446744073709551616")
	num("I05", "E", false, "1e3", "")
	num("I06", "E", false, "1.0", "")
	num("I07", "E", false, "1.5", "")
	num("I08", "E", false, "-0", "")
	num("I09", "E", false, "-1", "")
	num("I10", "X", false, "1e999", "!")
	num("I11", "R", true, "NaN", "")
	num("I12", "R", true, "Infinity", "")
	num("I13", "R", true, "0x10", "")
	num("I14", "R", true, "007", "")
	num("I15", "E", false, `"2"`, "")
	num("I16", "E", false, "true", "")
	num("I17", "E", false, "null", "")
	big := repeatStr("7", 1000)
	num("I18", "X", false, big, big)
	num("I19", "X", false, "-9223372036854775809", "-9223372036854775809")
	num("I20", "X", false, "12345678901234567890", "12345678901234567890")
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
