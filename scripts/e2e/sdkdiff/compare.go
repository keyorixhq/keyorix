package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxJSONDoc caps how much of one JSON document the harness decodes; a driver or
// server response beyond it is treated as not JSON rather than buffered whole.
const maxJSONDoc = 64 << 20

// NReq is a normalised wire request (see PREREGISTRATION.md section 2).
type NReq struct {
	Method  string
	Path    string
	Query   []string
	Auth    string
	CT      string
	Body    string
	HasBody bool
	RawQ    string
}

func normReq(r Rec) NReq {
	rawPath, rawQ, _ := strings.Cut(r.RequestURI, "?")
	n := NReq{Method: r.Method, RawQ: rawQ}
	if p, err := url.PathUnescape(rawPath); err == nil {
		n.Path = p
	} else {
		n.Path = "RAW:" + rawPath
	}
	if q, err := url.ParseQuery(rawQ); err == nil {
		for k, vs := range q {
			for _, v := range vs {
				n.Query = append(n.Query, k+"="+v)
			}
		}
		sort.Strings(n.Query)
	} else {
		n.Query = []string{"RAW:" + rawQ}
	}
	n.Auth = strings.Join(r.Header["Authorization"], "|")
	if ct := strings.Join(r.Header["Content-Type"], "|"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil {
			n.CT = mt
		} else {
			n.CT = strings.ToLower(ct)
		}
	}
	n.HasBody = len(r.Body) > 0
	n.Body = canonJSONBytes(r.Body)
	return n
}

// canonJSONBytes re-serialises JSON with sorted keys and exact numbers; non-JSON is compared as hex.
func canonJSONBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(b), maxJSONDoc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return "RAW:" + hex.EncodeToString(b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// view is one SDK's outcome for one step, reduced to comparable form.
type view struct {
	sdk    string
	skip   string // na | inexpressible | driver_error | not_run
	ok     bool
	class  string
	status string
	value  string
	msg    string
	ms     int64
	reqs   []NReq
	recs   []Rec
	raw    map[string]any
}

// Masking carries seed maxima so rows created during a scenario are compared by shape only.
type Masking struct{ ProjectMax, EnvMax float64 }

func toView(sdk string, so StepOutcome, m Masking, tok string) view {
	v := view{sdk: sdk, raw: so.Drv, recs: so.Reqs}
	for _, r := range so.Reqs {
		n := normReq(r)
		if tok != "" {
			// every SDK talks to its own server copy, hence holds its own session token
			n.Auth = strings.ReplaceAll(n.Auth, tok, "<instance-token>")
		}
		v.reqs = append(v.reqs, n)
	}
	d := so.Drv
	switch {
	case d == nil:
		v.skip = "not_run"
	case d["na"] == true:
		v.skip = "na"
	case d["inexpressible"] == true:
		v.skip = "inexpressible"
	case d["driver_error"] != nil:
		v.skip = "driver_error"
	}
	if v.skip != "" {
		return v
	}
	if n, ok := d["ms"].(json.Number); ok {
		v.ms, _ = n.Int64()
	}
	if d["ok"] == true {
		v.ok = true
		v.value = canonValue(d["value"], m)
		return v
	}
	v.class, _ = d["class"].(string)
	if s, ok := d["status"].(json.Number); ok {
		v.status = s.String()
	}
	v.msg, _ = d["msg"].(string)
	return v
}

// canonValue renders a driver value as canonical JSON with volatile fields masked.
func canonValue(v any, m Masking) string {
	b, _ := json.Marshal(maskVal(v, m))
	return string(b)
}

func maskVal(v any, m Masking) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = maskVal(x, m)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		volatile := false
		if n, ok := t["id"].(json.Number); ok {
			f, _ := n.Float64()
			_, hasDesc := t["description"]
			_, hasPID := t["project_id"]
			_, hasType := t["type"]
			switch {
			case hasDesc && f > m.ProjectMax: // project
				volatile = true
			case hasPID && !hasType && f > m.EnvMax: // environment
				volatile = true
			}
		}
		for k, x := range t {
			if k == "created_at" {
				out[k] = canonTime(x, volatile)
				continue
			}
			if volatile && k == "id" {
				out[k] = "<volatile-id>"
				continue
			}
			out[k] = maskVal(x, m)
		}
		return out
	}
	return v
}

func canonTime(x any, volatile bool) any {
	s, ok := x.(string)
	if !ok {
		return x
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		if volatile {
			return "<volatile-time>"
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	return s
}

// partition groups SDK names by key; blocks are sorted for stable output.
func partition(vs []view, key func(view) string) ([][]string, map[string]string) {
	idx := map[string][]string{}
	for _, v := range vs {
		k := key(v)
		idx[k] = append(idx[k], v.sdk)
	}
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return idx[keys[i]][0] < idx[keys[j]][0] })
	var blocks [][]string
	rep := map[string]string{}
	for _, k := range keys {
		sort.Strings(idx[k])
		blocks = append(blocks, idx[k])
		rep[strings.Join(idx[k], ",")] = k
	}
	return blocks, rep
}

func reqAt(v view, j int, f func(NReq) string) string {
	if j >= len(v.reqs) {
		return "<none>"
	}
	return f(v.reqs[j])
}

func maxReqs(vs []view) int {
	m := 0
	for _, v := range vs {
		if len(v.reqs) > m {
			m = len(v.reqs)
		}
	}
	return m
}

// compareStep applies the partition oracles to one step and returns findings.
func compareStep(scID string, step int, op string, vs []view) []Finding {
	var comparable []view
	for _, v := range vs {
		if v.skip == "" {
			comparable = append(comparable, v)
		}
	}
	if len(comparable) < 2 {
		return nil
	}
	var out []Finding
	add := func(cat, shape, detail string, blocks [][]string) {
		if len(blocks) > 1 {
			out = append(out, Finding{Cat: cat, Op: op, Step: step, Blocks: blocks, Shape: shape, Detail: detail, ScenarioI: scID})
		}
	}

	// wire oracles
	if op != "construct" {
		b, rep := partition(comparable, func(v view) string { return fmt.Sprint(len(v.reqs)) })
		add("W6", "count", fmt.Sprint(rep), b)
		n := maxReqs(comparable)
		for j := range n {
			// request #j is compared only among SDKs that made one; differences in the
			// number of requests are reported once, as W6
			var have []view
			for _, v := range comparable {
				if len(v.reqs) > j {
					have = append(have, v)
				}
			}
			if len(have) < 2 {
				continue
			}
			comparable := have
			b, rep := partition(comparable, func(v view) string { return reqAt(v, j, func(r NReq) string { return r.Method + " " + r.Path }) })
			add("W1", pathShape(rep), fmt.Sprintf("req#%d %v", j, rep), b)
			b, rep = partition(comparable, func(v view) string { return reqAt(v, j, func(r NReq) string { return strings.Join(r.Query, "&") }) })
			add("W2", queryShape(rep), fmt.Sprintf("req#%d %v", j, rep), b)
			b, rep = partition(comparable, func(v view) string { return reqAt(v, j, func(r NReq) string { return r.Auth }) })
			add("W3", authShape(rep), fmt.Sprintf("req#%d %v", j, redactAuth(rep)), b)
			b, rep = partition(comparable, func(v view) string {
				return reqAt(v, j, func(r NReq) string { return fmt.Sprint(r.HasBody) + r.Body })
			})
			add("W4", bodyShape(rep), fmt.Sprintf("req#%d %v", j, rep), b)
			b, rep = partition(comparable, func(v view) string { return reqAt(v, j, func(r NReq) string { return r.CT }) })
			add("W5", "ct", fmt.Sprintf("req#%d %v", j, rep), b)
		}
	}
	// outcome oracles
	b, _ := partition(comparable, func(v view) string { return fmt.Sprint(v.ok) })
	if len(b) > 1 {
		cat := "R2"
		if op == "construct" {
			cat = "V1"
		}
		add(cat, "ok-vs-err", errSummary(comparable), b)
		return out // value/class comparisons are meaningless once ok-ness differs
	}
	if comparable[0].ok {
		b, rep := partition(comparable, func(v view) string { return v.value })
		add("R1", valueShape(rep), clipStr(fmt.Sprint(rep)), b)
	} else {
		b, rep := partition(comparable, func(v view) string { return v.class })
		add("E1", classShape(comparable), fmt.Sprint(rep), b)
		var withStatus []view
		for _, v := range comparable {
			if v.status != "" {
				withStatus = append(withStatus, v)
			}
		}
		if len(withStatus) > 1 {
			b, rep := partition(withStatus, func(v view) string { return v.status })
			add("E2", "status", fmt.Sprint(rep), b)
		}
	}
	return out
}

func errSummary(vs []view) string {
	var parts []string
	for _, v := range vs {
		if v.ok {
			parts = append(parts, v.sdk+"=ok")
		} else {
			parts = append(parts, v.sdk+"="+v.class+"/"+v.status)
		}
	}
	return strings.Join(parts, " ")
}

func classShape(vs []view) string {
	set := map[string]bool{}
	for _, v := range vs {
		set[v.class] = true
	}
	var ks []string
	for k := range set {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	srv := "none"
	for _, v := range vs {
		if len(v.recs) > 0 {
			st := v.recs[len(v.recs)-1].RespStatus
			switch {
			case st == 401:
				srv = "401"
			case st > 0:
				srv = fmt.Sprintf("%dxx", st/100)
			}
			break
		}
	}
	return "classes=" + strings.Join(ks, "+") + " srv=" + srv
}

func pathShape(rep map[string]string) string {
	var ps []string
	for _, p := range rep {
		ps = append(ps, strings.TrimPrefix(p, "GET "))
	}
	if len(ps) == 2 {
		a, b := ps[0], ps[1]
		switch {
		case strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/"):
			return "trailing-slash"
		case strings.ReplaceAll(a, "//", "/") == strings.ReplaceAll(b, "//", "/"):
			return "dup-slash"
		}
	}
	return "path"
}

func queryShape(rep map[string]string) string {
	names := map[string]bool{}
	for _, q := range rep {
		for kv := range strings.SplitSeq(q, "&") {
			k, _, _ := strings.Cut(kv, "=")
			names[k] = true
		}
	}
	// keep only names whose value sets differ between blocks
	var diff []string
	for k := range names {
		seen := map[string]bool{}
		for _, q := range rep {
			val := "<absent>"
			for kv := range strings.SplitSeq(q, "&") {
				if kk, vv, _ := strings.Cut(kv, "="); kk == k {
					val = vv
				}
			}
			seen[val] = true
		}
		if len(seen) > 1 {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return "keys=" + strings.Join(diff, ",")
}

func authShape(rep map[string]string) string {
	var s []string
	for _, a := range rep {
		w, _, _ := strings.Cut(a, " ")
		if len(w) > 12 {
			w = w[:12]
		}
		s = append(s, w)
	}
	sort.Strings(s)
	return "scheme=" + strings.Join(s, "/")
}

func redactAuth(rep map[string]string) map[string]string {
	o := map[string]string{}
	for k, v := range rep {
		w, rest, _ := strings.Cut(v, " ")
		o[k] = w + " <len " + fmt.Sprint(len(rest)) + ">"
	}
	return o
}

func bodyShape(rep map[string]string) string {
	var docs []map[string]any
	for _, b := range rep {
		b = strings.TrimPrefix(strings.TrimPrefix(b, "true"), "false")
		var m map[string]any
		if json.Unmarshal([]byte(b), &m) == nil {
			docs = append(docs, m)
		} else {
			docs = append(docs, nil)
		}
	}
	if len(docs) == 2 && docs[0] != nil && docs[1] != nil {
		keys := map[string]bool{}
		for k := range docs[0] {
			keys[k] = true
		}
		for k := range docs[1] {
			keys[k] = true
		}
		var d []string
		for k := range keys {
			if fmt.Sprint(docs[0][k]) != fmt.Sprint(docs[1][k]) {
				d = append(d, k)
			}
		}
		sort.Strings(d)
		return "keys=" + strings.Join(d, ",")
	}
	return "body"
}

func valueShape(rep map[string]string) string {
	var vals []any
	for _, s := range rep {
		var v any
		dec := json.NewDecoder(io.LimitReader(strings.NewReader(s), maxJSONDoc))
		dec.UseNumber()
		_ = dec.Decode(&v)
		vals = append(vals, v)
	}
	if len(vals) >= 2 {
		return "at=" + firstDiffPath(vals[0], vals[1], "$")
	}
	return "value"
}

func firstDiffPath(a, b any, p string) string {
	switch x := a.(type) {
	case []any:
		y, ok := b.([]any)
		if !ok {
			return p + "(type)"
		}
		if len(x) != len(y) {
			return p + "(len)"
		}
		for i := range x {
			if d := firstDiffPath(x[i], y[i], p+"[]"); d != "" {
				return d
			}
		}
		return ""
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			return p + "(type)"
		}
		keys := map[string]bool{}
		for k := range x {
			keys[k] = true
		}
		for k := range y {
			keys[k] = true
		}
		var ks []string
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			if d := firstDiffPath(x[k], y[k], p+"."+k); d != "" {
				return d
			}
		}
		return ""
	}
	if fmt.Sprint(a) != fmt.Sprint(b) {
		return p
	}
	return ""
}

// credentialInBody reports whether a recorded request body carries the synthetic login password
// or the session token (len >= 8, to avoid matching short or empty tokens) verbatim.
func credentialInBody(body []byte, token string) bool {
	b := string(body)
	if strings.Contains(b, adminPW) {
		return true
	}
	return len(token) >= 8 && strings.Contains(b, token)
}

// absoluteChecks applies the per-SDK oracles E3, S1, S2 and T1.
func absoluteChecks(scID string, step int, st Step, vs []view, spec *Spec, tokenOf func(string) string) []Finding {
	var out []Finding
	for _, v := range vs {
		if v.skip != "" {
			continue
		}
		token := tokenOf(v.sdk)
		one := func(cat, shape, detail string) {
			out = append(out, Finding{Cat: cat, Op: st.Op, Step: step, Blocks: [][]string{{v.sdk}}, Shape: shape, Detail: detail, ScenarioI: scID})
		}
		if !v.ok {
			for _, r := range v.recs {
				if len(r.RespBody) >= 8 && !strings.HasSuffix(r.RespBody, "[cut]") && strings.Contains(v.msg, strings.TrimSpace(r.RespBody)) {
					one("E3", "body-in-message", "error message contains the server response body")
					break
				}
			}
			if len(token) >= 8 {
				quoted := strconv.Quote(token)
				quoted = quoted[1 : len(quoted)-1]
				if strings.Contains(v.msg, token) || strings.Contains(v.msg, quoted) {
					one("E3", "token-in-message", "error message contains the bearer token")
				}
			}
		}
		// S1 only for the first request of a step with an ordinary base URL: later requests
		// follow a redirect, and the odd base variants are malformed on purpose
		if spec != nil && len(v.recs) > 0 && (st.Base == "" || st.Base == "plain" || st.Base == "slash" || st.Base == "upper_scheme") {
			r := v.recs[0]
			if r.Faulted == "" || r.Faulted == "slow" {
				if why := spec.Check(r.Method, r.RequestURI); why != "" {
					one("S1", why, r.Method+" "+clipStr(r.RequestURI))
				}
			}
		}
		// X1: a credential must not follow a redirect to another origin. Covers an Authorization
		// header (A5) and, since A12, the login password or this instance's session token in the
		// request body. Not covered: a credential in the URL, in another header or in a form of
		// the secret other than the verbatim string (encoded, hashed).
		for _, r := range v.recs {
			if h := r.Header["Host"]; len(h) > 0 && strings.HasPrefix(h[0], "localhost:") {
				if len(r.Header["Authorization"]) > 0 {
					one("X1", "authorization-sent-to-other-origin", r.Method+" "+clipStr(r.RequestURI))
					break
				}
				if credentialInBody(r.Body, token) {
					one("X1", "credential-in-body-sent-to-other-origin", r.Method+" "+clipStr(r.RequestURI))
					break
				}
			}
		}
		if st.Expect == "ok" && !v.ok {
			one("S2", "valid-step-failed", v.class+"/"+v.status)
		}
		if st.TimeoutMs > 0 && st.Fault != nil && st.Fault.Kind == "slow" && st.Fault.Ms >= 3*st.TimeoutMs {
			if v.ok || v.ms > int64(3*st.TimeoutMs+1000) {
				one("T1", "timeout-not-enforced", fmt.Sprintf("timeout=%dms delay=%dms took=%dms ok=%v", st.TimeoutMs, st.Fault.Ms, v.ms, v.ok))
			}
		}
	}
	return out
}
