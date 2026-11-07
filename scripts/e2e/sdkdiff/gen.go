package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// Edge-value pools (PREREGISTRATION.md section 5).
var (
	specials = []string{" ", "+", "%", "&", "=", "#", "?", "/", "\\", ";", ":", "@", "\"", "'", "<", ">", "~", "*", "!", "(", ")",
		"a b", "a+b", "a%2Fb", "%2F", "%00", "%25", "a&b=c", "x=1&y=2", "../", "..", ".", "/prefix/", "a/b", "a?b", "a#b", "\u2028", "\u00a0"}
	unicodes = []string{"café", "café", "Å", "Å", "ẛ̣", "ẹ́", "é", "é",
		"\u200d", "\u202e", "\ufeff", "\U0001F468\u200d\U0001F469\u200d\U0001F467", "\U0001F600", "日本語", "שלום", "İ", "ß", "ǅ", "Ａ"}
	controls = []string{"\u0000", "a\u0000b", "\r\n", "a\r\nb: c", "\t", "\u0007", "\u001b[0m", "\u007f", "\n", "\r"}
	seeded   = []string{"db-password", "api key", "naïve-nfc", "naïve-nfc", "q&a=b?c#d/e", "100%25-lit", "plus+sign", `quote"and\back`,
		"emoji-\U0001F600-name", "val-unicode", "val-newline", "val-quotes", "val-json", "val-key-lookalike", "val-space", "val-long", "val-control",
		"filler-00", "filler-29", "zz-late", "missing-secret"}
	envs = []string{"", "production", "staging", "development", "PRODUCTION", "prod uction", "missing-env"}
	ids  = []string{"0", "1", "2", "3", "4", "5", "-1", "-9", "2147483647", "2147483648", "4294967295", "4294967296",
		"9007199254740991", "9007199254740992", "9007199254740993", "9223372036854775807", "9223372036854775808",
		"18446744073709551615", "18446744073709551616", "99999999999999999999", "007", "1000000"}
	longLens   = []int{256, 255, 1024, 8192, 65536}
	badBodies  = []string{"CANARY-BODY-5d41402abc4b2a76", `{"error":"CANARY-BODY-5d41402abc4b2a76","detail":"x"}`, "<html>CANARY-BODY-5d41402abc4b2a76</html>"}
	constructs = []string{"https://example.com", "http://localhost", "http://127.0.0.1", "http://[::1]:8080", "http://127.0.0.2", "http://127.1",
		"http://127.300.1.1", "http://127.0.0.1.evil.com", "http://localhost.evil.com", "http://LOCALHOST", "http://localhost.", "http://0.0.0.0",
		"http://0x7f.0.0.1", "http://2130706433", "http://[::ffff:127.0.0.1]", "ftp://x", "file:///etc/passwd", "", "localhost:8080",
		"//localhost", "http://", "https://", "HTTPS://X", " https://example.com", "https://example.com ", "http://user@localhost",
		"http://localhost@evil.com", "http://evil.com#@localhost", "http://evil.com\\@localhost", "http://localhost\u0000.evil.com",
		"https://éxample.com", "HtTp://localhost", "http://LocalHost:80", "http://[::1]", "http://127.0.0.1\n", "http://127.0.0.1\t.evil.com",
		"http://127.0.0.1:99999", "http://127.0.0.1:abc", "https://exa mple.com", "http://[::1", "http://localhost%2f.evil.com", "http://ｌｏｃａｌｈｏｓｔ",
		"http://127.0.0.1@evil.com", "http://localhost:80@evil.com", "http://127.000.000.001", "http://127.0.0.1.", "http://[0:0:0:0:0:0:0:1]", "http://[::1%25lo]"}
)

func longStr(n int) string { return strings.Repeat("a", n) }

func edgeStrings() []string {
	var all []string
	all = append(all, specials...)
	all = append(all, unicodes...)
	all = append(all, controls...)
	all = append(all, seeded...)
	all = append(all, "", "a", "x y")
	for _, n := range longLens {
		all = append(all, longStr(n))
	}
	return all
}

func pick(r *rand.Rand, s []string) string { return s[r.Intn(len(s))] }

func randString(r *rand.Rand) string {
	switch r.Intn(8) {
	case 0:
		return pick(r, specials)
	case 1:
		return pick(r, unicodes)
	case 2:
		return pick(r, controls)
	case 3:
		return pick(r, seeded)
	case 4:
		return pick(r, specials) + pick(r, unicodes) + pick(r, []string{"", "x", "1"})
	case 5:
		if r.Intn(10) == 0 {
			return longStr(longLens[r.Intn(len(longLens))])
		}
		return "plain"
	case 6:
		return pick(r, envs)
	}
	return pick(r, seeded)
}

func randArg(r *rand.Rand, pool []string, nullable bool) Arg {
	if nullable && r.Intn(6) == 0 {
		return Null()
	}
	if len(pool) > 0 && r.Intn(2) == 0 {
		return S(pick(r, pool))
	}
	return S(randString(r))
}

func randBase(r *rand.Rand) string {
	if r.Intn(5) != 0 {
		return ""
	}
	return pick(r, []string{"slash", "slash2", "upper_scheme", "userinfo", "query", "fragment", "prefix"})
}

func randToken(r *rand.Rand) string {
	if r.Intn(6) != 0 {
		return ""
	}
	return pick(r, []string{"empty", "canary", "space", "crlf", "unicode", "long"})
}

func randFault(r *rand.Rand) *Fault {
	if r.Intn(5) != 0 {
		return nil
	}
	switch r.Intn(9) {
	case 0:
		return &Fault{Kind: "status", Status: pick3(r), Body: pick(r, badBodies)}
	case 1:
		return &Fault{Kind: "close"}
	case 2:
		return &Fault{Kind: "redirect", Status: []int{301, 302, 307, 308}[r.Intn(4)], Location: pick(r, []string{"/health", "/api/v1/projects", "http://127.0.0.1:1/x"})}
	case 3:
		return &Fault{Kind: "empty200"}
	case 4:
		return &Fault{Kind: "badjson200"}
	case 5:
		return &Fault{Kind: "html200"}
	case 6:
		return &Fault{Kind: "wrongtype200"}
	case 7:
		return &Fault{Kind: "null_data200"}
	}
	return &Fault{Kind: "nodata200"}
}

func pick3(r *rand.Rand) int {
	return []int{400, 401, 403, 404, 409, 422, 429, 500, 502, 503}[r.Intn(10)]
}

func (s Step) withClient(r *rand.Rand) Step {
	s.Base, s.Token, s.Fault = randBase(r), randToken(r), randFault(r)
	return s
}

// genRandom builds one phase-B scenario from a seed.
func genRandom(seed int64) Scenario {
	r := rand.New(rand.NewSource(seed))
	sc := Scenario{ID: fmt.Sprintf("B-%06d", seed)}
	n := 1 + r.Intn(6)
	lastCreate, lastList := -1, -1
	for i := 0; i < n; i++ {
		var st Step
		switch r.Intn(10) {
		case 0:
			st = Step{Op: "health"}
		case 1:
			st = Step{Op: "login", Args: []Arg{randArg(r, []string{adminUser, "nobody"}, true), randArg(r, []string{adminPW, "wrong"}, true)}}
		case 2, 3:
			st = Step{Op: "list_secrets", Args: []Arg{randArg(r, envs, true)}}
		case 4, 5:
			st = Step{Op: "get_secret", Args: []Arg{randArg(r, seeded, false), randArg(r, envs, true)}}
		case 6:
			st = Step{Op: "list_projects"}
			lastList = i
		case 7:
			name := S(fmt.Sprintf("s%d-%d-%s", seed, i, randString(r)))
			st = Step{Op: "create_project", Args: []Arg{name, randArg(r, []string{"", "desc"}, true)}}
			lastCreate = i
		case 8:
			var a Arg
			switch {
			case lastCreate >= 0 && r.Intn(2) == 0:
				a = Arg{Ref: &Ref{Step: lastCreate, Path: "id"}}
			case lastList >= 0 && r.Intn(2) == 0:
				a = Arg{Ref: &Ref{Step: lastList, Path: "[0].id"}}
			default:
				a = S(pick(r, ids))
			}
			st = Step{Op: "list_environments", Args: []Arg{a}}
		default:
			st = Step{Op: "construct", Base: "literal:" + pick(r, constructs)}
		}
		if st.Op != "construct" {
			st = st.withClient(r)
			if r.Intn(25) == 0 {
				st.TimeoutMs = 200
				if r.Intn(2) == 0 {
					st.Fault = &Fault{Kind: "slow", Ms: 4000}
				}
			}
		}
		sc.Steps = append(sc.Steps, st)
	}
	return sc
}

// genMatrix builds the deterministic phase-A edge matrix.
func genMatrix() []Scenario {
	var out []Scenario
	n := 0
	add := func(tags []string, st ...Step) {
		n++
		out = append(out, Scenario{ID: fmt.Sprintf("A-%05d", n), Tags: append([]string{"validation"}, tags...), Steps: st})
	}
	es := edgeStrings()
	// golden set (control C2)
	for _, st := range [][]Step{
		{{Op: "health", Expect: "ok"}},
		{{Op: "list_environments", Args: []Arg{S("2")}, Expect: "ok"}},
		{{Op: "create_project", Args: []Arg{S("golden-one"), S("d")}, Expect: "ok"}},
		{{Op: "login", Args: []Arg{S(adminUser), S(adminPW)}, Expect: "ok"}},
		{{Op: "construct", Base: "literal:https://example.com", Expect: "ok"}},
		{{Op: "construct", Base: "literal:http://127.0.0.1:8080", Expect: "ok"}},
	} {
		add([]string{"golden"}, st...)
	}
	for _, e := range es {
		add([]string{"edge-env"}, Step{Op: "list_secrets", Args: []Arg{S(e)}})
	}
	for _, e := range es {
		add([]string{"edge-name"}, Step{Op: "get_secret", Args: []Arg{S(e), S("")}})
	}
	for _, e := range envs {
		add([]string{"edge-env"}, Step{Op: "get_secret", Args: []Arg{S("db-password"), S(e)}})
	}
	add([]string{"edge-null"}, Step{Op: "list_secrets", Args: []Arg{Null()}})
	add([]string{"edge-null"}, Step{Op: "get_secret", Args: []Arg{S("db-password"), Null()}})
	add([]string{"edge-null"}, Step{Op: "get_secret", Args: []Arg{Null(), S("")}})
	for i, e := range es {
		add([]string{"edge-create"}, Step{Op: "create_project", Args: []Arg{S(fmt.Sprintf("a%d-%s", i, e)), S("")}})
		add([]string{"edge-create"}, Step{Op: "create_project", Args: []Arg{S(fmt.Sprintf("a%d-d", i)), S(e)}})
	}
	add([]string{"edge-null"}, Step{Op: "create_project", Args: []Arg{S("a-null-desc"), Null()}})
	add([]string{"edge-null"}, Step{Op: "create_project", Args: []Arg{Null(), S("")}})
	add([]string{"edge-create"}, Step{Op: "create_project", Args: []Arg{S("a-empty-name"), S("")}}, Step{Op: "create_project", Args: []Arg{S(""), S("")}})
	add([]string{"edge-create"}, Step{Op: "create_project", Args: []Arg{S("a-dup"), S("")}}, Step{Op: "create_project", Args: []Arg{S("a-dup"), S("")}})
	add([]string{"edge-create"}, Step{Op: "create_project", Args: []Arg{S("a-flow"), S("")}}, Step{Op: "list_environments", Args: []Arg{{Ref: &Ref{Step: 0, Path: "id"}}}}, Step{Op: "list_projects"})
	for _, id := range ids {
		add([]string{"edge-id"}, Step{Op: "list_environments", Args: []Arg{S(id)}})
	}
	for _, e := range es {
		add([]string{"edge-login"}, Step{Op: "login", Args: []Arg{S(e), S(adminPW)}})
		add([]string{"edge-login"}, Step{Op: "login", Args: []Arg{S(adminUser), S(e)}})
	}
	for _, c := range constructs {
		add([]string{"edge-construct"}, Step{Op: "construct", Base: "literal:" + c})
	}
	ops := []Step{{Op: "health"}, {Op: "list_secrets", Args: []Arg{S("")}}, {Op: "get_secret", Args: []Arg{S("db-password"), S("")}}, {Op: "list_projects"},
		{Op: "create_project", Args: []Arg{S("a-base"), S("d")}}, {Op: "list_environments", Args: []Arg{S("1")}}, {Op: "login", Args: []Arg{S(adminUser), S(adminPW)}}}
	for i, op := range ops {
		for _, b := range []string{"slash", "slash2", "upper_scheme", "userinfo", "query", "fragment", "prefix"} {
			s := op
			s.Base = b
			if op.Op == "create_project" {
				s.Args = []Arg{S(fmt.Sprintf("a-base-%d-%s", i, b)), S("d")}
			}
			add([]string{"edge-base"}, s)
		}
		for _, t := range []string{"empty", "canary", "space", "crlf", "unicode", "long"} {
			s := op
			s.Token = t
			if op.Op == "create_project" {
				s.Args = []Arg{S(fmt.Sprintf("a-tok-%d-%s", i, t)), S("d")}
			}
			add([]string{"edge-token"}, s)
		}
		for _, code := range []int{400, 401, 403, 404, 409, 422, 429, 500, 502, 503} {
			for _, body := range badBodies[:2] {
				s := op
				s.Fault = &Fault{Kind: "status", Status: code, Body: body}
				s.Token = "canary"
				add([]string{"fault-status"}, s)
			}
		}
		for _, k := range []string{"close", "empty200", "badjson200", "html200", "wrongtype200", "null_data200", "nodata200"} {
			s := op
			s.Fault = &Fault{Kind: k}
			add([]string{"fault-" + k}, s)
		}
		for _, loc := range []string{"/health", "/api/v1/projects"} {
			for _, code := range []int{301, 302, 307, 308} {
				s := op
				s.Fault = &Fault{Kind: "redirect", Status: code, Location: loc}
				add([]string{"fault-redirect"}, s)
			}
		}
		s := op
		s.Fault = &Fault{Kind: "bigbody", Bytes: 8 << 20}
		add([]string{"fault-bigbody"}, s)
		s = op
		s.TimeoutMs = 200
		s.Fault = &Fault{Kind: "slow", Ms: 4000}
		add([]string{"fault-timeout"}, s)
	}
	return out
}
