package livereplay

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Probe is one request the replay sends.
type Probe struct {
	Variant   string // swap | cross | idmut | list | batch
	Actor     string
	OpKey     string
	Method    string
	Target    string // path?query
	Body      []byte
	ObjTenant string // tenant owning the object ids the request carries, "" if none
	Desc      string
}

// Result classes. Everything starting with "CANDIDATE" needs a human verdict.
const (
	ClassOK             = "ok"
	ClassInconclusive   = "inconclusive"
	ClassCandStatus     = "CANDIDATE-STATUS" // success for an actor the model denies
	ClassCandLeak       = "CANDIDATE-LEAK"   // another tenant's canary in the response
	ClassCandEffect     = "CANDIDATE-EFFECT" // state changed after a probe the model denies
	ClassModelRefused   = "model-allow-refused"
	ClassServerError    = "server-error"
	ClassControlOK      = "control-ok"
	ClassControlRefused = "control-refused"
)

// Result is a probe plus what came back and how it was classified.
type Result struct {
	Probe
	Status  int
	Verdict Verdict
	Class   string
	Detail  string
	Resp    string // first bytes of the response body (private output only)
}

// IsCandidate reports whether the class needs a verdict.
func (r Result) IsCandidate() bool { return strings.HasPrefix(r.Class, "CANDIDATE") }

// Key identifies a candidate across runs: it is stable when the world is
// rebuilt from scratch, because ids are assigned in a fixed order.
func (r Result) Key() string {
	return r.Class + "|" + r.Variant + "|" + r.Actor + "|" + r.Method + " " + r.Target
}

var destructiveWords = []string{"delete", "suspend", "revoke", "rotate", "restore", "bulk", "reassign", "move", "rollback", "disable", "remove", "logout", "purge", "reset", "expire", "revoke-all", "transfer"}

func isDestructive(op Op) bool {
	if op.Method == "DELETE" {
		return true
	}
	p := strings.ToLower(op.Path)
	for _, w := range destructiveWords {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}

// selfOps are session-management routes of the acting credential itself; a
// real actor must not run them against itself or the world loses its logins.
func selfOp(op Op) bool {
	for _, p := range []string{"/api/v1/auth/logout", "/api/v1/auth/change-password", "/api/v1/auth/mfa", "/api/v1/auth/sessions", "/api/v1/auth/end-impersonation", "/api/v1/auth/profile"} {
		if strings.HasPrefix(op.Path, p) && op.Method != "GET" {
			return true
		}
	}
	return false
}

var tenantKinds = map[string]bool{"project": true, "env": true, "secret": true, "machine": true, "machinetoken": true, "share": true, "acl": true, "invitation": true, "accessrequest": true, "version": true, "group": true, "pat": true}

// tenantQueryOps are single-object reads addressed by query, not path.
var tenantQueryOps = map[string]bool{"/api/v1/secrets/value": true, "/api/v1/secrets/by-name": true}

// idKeys maps request-body keys to the kind of id they carry.
var idKeys = map[string]string{
	"project_id": "project", "environment_id": "env", "env_id": "env", "secret_id": "secret",
	"secret_ids": "secret", "machine_id": "machine", "group_id": "group", "request_ids": "accessrequest",
	"recipient_id": "user", "user_id": "user", "source_project_id": "project", "target_project_id": "project",
	"target_environment_id": "env", "source_environment_id": "env", "project_ids": "project",
}

// fillBody substitutes tenant ids into a JSON body. It reports the tenant if
// any tenant-bearing id was written.
func (w *World) fillBody(body any, tenant string) (any, bool) {
	tenantIDUsed := false
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				if kind, ok := idKeys[k]; ok {
					id, have := w.FirstID(tenant, kind)
					if have {
						n, _ := strconv.Atoi(id)
						if _, isArr := x.([]any); isArr {
							t[k] = []any{n}
						} else {
							t[k] = n
						}
						if tenantKinds[kind] {
							tenantIDUsed = true
						}
						continue
					}
				}
				t[k] = walk(x)
			}
			return t
		case []any:
			for i, x := range t {
				t[i] = walk(x)
			}
			return t
		}
		return v
	}
	return walk(body), tenantIDUsed
}

// build makes the probe for (actor, op) with tenant's ids. ok=false when the
// op cannot be instantiated meaningfully for this tenant.
func (w *World) build(a *Actor, op Op, tenant, variant string) (Probe, bool) {
	p := Probe{Variant: variant, Actor: a.Name, OpKey: op.Key(), Method: op.Method}
	path := op.Path
	objTenant := ""
	for _, name := range PathParams(op.Path) {
		kind := ParamKind(op.Path, name)
		id, ok := w.FirstID(tenant, kind)
		if !ok {
			id = "1"
		} else if tenantKinds[kind] {
			objTenant = tenant
		}
		path = strings.Replace(path, "{"+name+"}", id, 1)
	}
	q := url.Values{}
	if tenantQueryOps[op.Path] {
		q.Set("ref", w.Refs[tenant])
		q.Set("name", strings.Split(w.Refs[tenant]+"//", "/")[2])
		if id, ok := w.FirstID(tenant, "project"); ok {
			q.Set("project_id", id)
		}
		if id, ok := w.FirstID(tenant, "env"); ok {
			q.Set("environment_id", id)
		}
		objTenant = tenant
	}
	for _, prm := range op.Params {
		if prm.In == "query" && prm.Required && q.Get(prm.Name) == "" {
			q.Set(prm.Name, "1")
		}
	}
	if op.Method != "GET" && op.Body != nil || op.Method == "POST" || op.Method == "PUT" || op.Method == "PATCH" {
		var raw any
		if rec := w.Recorded[op.Key()]; len(rec) > 0 && len(rec[0].Body) > 0 {
			_ = json.Unmarshal(rec[0].Body, &raw)
		}
		if raw == nil {
			raw = w.Spec.MinimalBody(op)
		}
		if raw != nil {
			filled, used := w.fillBody(raw, tenant)
			if used && objTenant == "" {
				objTenant = tenant
			}
			b, err := json.Marshal(filled)
			if err != nil {
				return p, false
			}
			p.Body = b
		} else if op.Method != "GET" {
			p.Body = []byte("{}")
		}
	}
	p.ObjTenant = objTenant
	p.Target = path
	if len(q) > 0 {
		p.Target += "?" + q.Encode()
	}
	return p, true
}

// Options tune a run.
type Options struct {
	// Only restricts the run to operations whose key contains this substring.
	Only string
	// SkipControl skips the legitimate actor's positive-control request.
	SkipControl bool
	// Log is called once per probe result (JSONL sink).
	Log func(Result)
}

func (w *World) orderedOps(only string) []Op {
	var ops []Op
	for _, o := range w.Spec.Ops {
		if !strings.HasPrefix(o.Path, "/api/v1/") {
			continue
		}
		if only != "" && !strings.Contains(o.Key(), only) {
			continue
		}
		ops = append(ops, o)
	}
	rank := func(o Op) int {
		switch {
		case o.Method == "GET":
			return 0
		case isDestructive(o):
			return 2
		}
		return 1
	}
	sort.SliceStable(ops, func(i, j int) bool { return rank(ops[i]) < rank(ops[j]) })
	return ops
}

// Run executes the whole replay and returns every result.
func (w *World) Run(opt Options) []Result {
	var results []Result
	// Quiescence check before any probe: paths that move on their own are
	// masked from the effect oracle and reported in w.DriftFound.
	w.DriftFound = w.Calibrate(3)
	emit := func(r Result) {
		results = append(results, r)
		if opt.Log != nil {
			opt.Log(r)
		}
	}
	for _, op := range w.orderedOps(opt.Only) {
		for _, p := range w.probesFor(op) {
			emit(w.exec(p, op))
		}
		if !opt.SkipControl && !isDestructive(op) && !selfOp(op) && !authorityChanging(op) {
			if a := w.Actors["A"]; a != nil {
				if p, ok := w.build(a, op, "A", "control"); ok {
					r := w.exec(p, op)
					if r.Status >= 200 && r.Status < 300 {
						r.Class = ClassControlOK
					} else {
						r.Class = ClassControlRefused
					}
					emit(r)
				}
			}
		}
	}
	return results
}

// probesFor lists every attacker probe for op: actor swap with A's ids, A and
// V with B's ids (cross), mutated ids, list pagination/filters, batch bodies.
func (w *World) probesFor(op Op) []Probe {
	var out []Probe
	add := func(p Probe, ok bool) {
		if ok {
			out = append(out, p)
		}
	}
	for _, name := range w.Attackers {
		a := w.Actors[name]
		if a == nil || name == "A" {
			continue
		}
		if !a.DenyAll && selfOp(op) {
			continue
		}
		p, ok := w.build(a, op, "A", "swap")
		add(p, ok)
	}
	// A (and V) reaching for B's objects: the reverse direction of the same swap.
	for _, name := range []string{"A", "V"} {
		a := w.Actors[name]
		if a == nil || selfOp(op) {
			continue
		}
		p, ok := w.build(a, op, "B", "cross")
		if ok && p.ObjTenant == "B" {
			out = append(out, p)
		}
	}
	// Mutated ids: neighbours, zero, negative, overflow, traversal.
	if len(PathParams(op.Path)) > 0 && !selfOp(op) {
		for _, name := range []string{"A", "B"} {
			a := w.Actors[name]
			if a == nil {
				continue
			}
			base, ok := w.build(a, op, otherTenant(name), "idmut")
			if !ok {
				continue
			}
			for _, bad := range []string{"0", "-1", "99999999999999999999", "abc", "..%2f1", "1%00"} {
				m := base
				m.Desc = "id=" + bad
				m.Target = replaceFirstID(op, base.Target, bad)
				m.ObjTenant = "" // neighbour ids belong to nobody in particular: leak + effect oracles only
				out = append(out, m)
			}
			for _, d := range []int{-1, 1} {
				if t, ok := neighbour(base.Target, op, d); ok {
					m := base
					m.Desc = "neighbour" + strconv.Itoa(d)
					m.Target = t
					m.ObjTenant = ""
					out = append(out, m)
				}
			}
		}
	}
	// Lists: pagination and filter mutation, tenant ids in the filter.
	if op.Method == "GET" && len(PathParams(op.Path)) == 0 && !tenantQueryOps[op.Path] {
		qs := []string{
			"page=-1", "page=0&page_size=100000", "page_size=-5", "limit=-1", "limit=100000&offset=0",
			"cursor=AAAA", "search=lrcanary", "q=lrcanary", "name=lrcanary",
		}
		if id, ok := w.FirstID("A", "project"); ok {
			qs = append(qs, "project_id="+id, "project_id="+id+"&page_size=1000")
		}
		if id, ok := w.FirstID("A", "env"); ok {
			qs = append(qs, "environment_id="+id)
		}
		for _, name := range w.Attackers {
			a := w.Actors[name]
			if a == nil || name == "A" || name == "V" {
				continue
			}
			for _, q := range qs {
				p := Probe{Variant: "list", Actor: name, OpKey: op.Key(), Method: "GET", Desc: q}
				p.Target = op.Path + "?" + q
				out = append(out, p)
			}
		}
	}
	// Batches: A's ids mixed into the attacker's own batch.
	if op.Body != nil && batchOp(op) {
		for _, name := range []string{"B", "N", "V"} {
			a := w.Actors[name]
			if a == nil {
				continue
			}
			p, ok := w.build(a, op, "A", "batch")
			if ok {
				p.Desc = "A ids in attacker batch"
				out = append(out, p)
			}
		}
	}
	return out
}

func otherTenant(actor string) string {
	if actor == "A" {
		return "B"
	}
	return "A"
}

func batchOp(op Op) bool {
	props, _ := op.Body["properties"].(map[string]any)
	for k := range props {
		if strings.HasSuffix(k, "_ids") || k == "ids" || k == "items" {
			return true
		}
	}
	return false
}

var numSeg = func(s string) bool { _, err := strconv.Atoi(s); return err == nil }

func replaceFirstID(op Op, target, bad string) string {
	path, q := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		path, q = target[:i], target[i:]
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if numSeg(s) {
			segs[i] = bad
			break
		}
	}
	return strings.Join(segs, "/") + q
}

func neighbour(target string, op Op, d int) (string, bool) {
	path, q := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		path, q = target[:i], target[i:]
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if n, err := strconv.Atoi(s); err == nil {
			segs[i] = strconv.Itoa(n + d)
			return strings.Join(segs, "/") + q, true
		}
	}
	return "", false
}

// exec sends a probe and classifies the outcome.
func (w *World) exec(p Probe, op Op) Result {
	a := w.Actors[p.Actor]
	unsafe := p.Method != "GET"
	var before map[string]string
	if unsafe {
		before = w.Fingerprint()
	}
	status, body, err := w.Do(a, p.Method, p.Target, p.Body)
	r := Result{Probe: p, Status: status}
	if len(body) > 300 {
		r.Resp = string(body[:300])
	} else {
		r.Resp = string(body)
	}
	if err != nil {
		r.Class, r.Detail = ClassInconclusive, "transport: "+err.Error()
		return r
	}
	r.Verdict = Expect(a, op, p.ObjTenant)
	r.Class = ClassOK
	success := status >= 200 && status < 300
	denied := status == 401 || status == 403 || status == 404

	var sig []string
	var detail []string
	switch {
	case status >= 500:
		r.Class, r.Detail = ClassServerError, "5xx under hostile input"
	case r.Verdict == Deny && success:
		sig = append(sig, "STATUS")
		detail = append(detail, "model denies, server answered "+strconv.Itoa(status))
	case r.Verdict == Allow && (status == 401 || status == 403):
		r.Class = ClassModelRefused
	case status == 400 || status == 405 || status == 409 || status == 415 || status == 422 || status == 429 || (status == 404 && r.Verdict != Deny):
		r.Class = ClassInconclusive
	}
	_ = denied

	if leak := w.leaked(a, p, body); leak != "" {
		sig = append(sig, "LEAK")
		detail = append(detail, "response carries "+leak)
	}
	if unsafe {
		if ch := w.RealChanges(before); len(ch) > 0 && r.Verdict != Allow {
			var sus []string
			for _, path := range ch {
				own := !a.DenyAll && a.Role != "" && w.FPTenant[path] == a.Tenant && a.Tenant != ""
				if r.Verdict == Deny || !own {
					sus = append(sus, path)
				}
			}
			if len(sus) > 0 {
				sig = append(sig, "EFFECT")
				detail = append(detail, "state changed: "+strings.Join(sus, ", "))
			}
		}
	}
	if len(sig) > 0 {
		r.Class = "CANDIDATE-" + strings.Join(sig, "+")
		r.Detail = strings.Join(detail, "; ")
	}
	return r
}

// leaked returns the foreign marker found in the response ("" if none). A
// marker the request itself sent is not a leak (an echo).
func (w *World) leaked(a *Actor, p Probe, body []byte) string {
	lb := strings.ToLower(string(body))
	req := strings.ToLower(p.Target + string(p.Body))
	for _, t := range []string{"A", "B"} {
		if a.Tenant == t && !a.DenyAll {
			continue
		}
		m := w.Marker[t]
		if m != "" && strings.Contains(lb, m) && !strings.Contains(req, m) {
			return "tenant " + t + " marker"
		}
	}
	return ""
}

// Summary counts results by variant/actor/class.
func Summary(rs []Result) map[string]int {
	out := map[string]int{}
	for _, r := range rs {
		out[r.Variant+"/"+r.Actor+"/"+r.Class]++
	}
	return out
}

// Candidates returns the candidate results, in run order.
func Candidates(rs []Result) []Result {
	var out []Result
	for _, r := range rs {
		if r.IsCandidate() {
			out = append(out, r)
		}
	}
	return out
}
