package livereplay

// Planted-defect self-test, level 1 (default `go test`, ~1s): the replay
// library runs against a tiny in-process multi-tenant API (httptest) whose
// authorization is correct, then once per planted defect. A clean API must
// produce zero candidates and every planted defect must be reported, on the
// planted operation only. Level 2 (live_e2e_test.go, -tags e2e) does the same
// to the real keyorix-server by building it from a source overlay.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeSecret struct {
	tenant string
	name   string
	value  string
}

type fakeUser struct{ tenant, role string }

type fakeAPI struct {
	reads   int // observer-visible counter bumped by every authorised GET (self-drift)
	mu      sync.Mutex
	plant   string
	users   map[string]fakeUser
	secrets map[int]*fakeSecret
}

func newFakeAPI(plant string) *fakeAPI {
	return &fakeAPI{
		plant: plant,
		users: map[string]fakeUser{
			"tokA": {"A", "admin"}, "tokV": {"A", "viewer"}, "tokB": {"B", "admin"},
			"tokN": {"", ""}, "tokRoot": {"*", "admin"},
		},
		secrets: map[int]*fakeSecret{
			1: {"A", "lrcanary-a-s1", "lrcanary-a-v1"},
			2: {"A", "lrcanary-a-s2", "lrcanary-a-v2"},
			3: {"B", "lrcanary-b-s3", "lrcanary-b-v3"},
		},
	}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	u, authed := f.users[tok]
	if !authed && !(f.plant == "noauth" && r.URL.Path == "/api/v1/projects/1/secrets") {
		reply(401, map[string]string{"error": "unauthenticated"})
		return
	}
	member := func(t string) bool { return u.tenant == "*" || (u.tenant == t && t != "") }
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /api/v1/users/{id}: install-wide identity writes belong to the global admin only
	if len(segs) == 4 && segs[2] == "users" && r.Method == "PUT" {
		if u.tenant == "*" || f.plant == "userwrite" {
			reply(200, map[string]string{"ok": "updated"})
			return
		}
		reply(403, map[string]string{"error": "forbidden"})
		return
	}
	// /api/v1/secrets[/{id}]
	if len(segs) >= 3 && segs[2] == "secrets" {
		if len(segs) == 3 {
			switch r.Method {
			case "GET":
				var out []map[string]string
				q := r.URL.Query().Get("search")
				for _, s := range f.secrets {
					if member(s.tenant) || (f.plant == "leak" && q != "") {
						out = append(out, map[string]string{"name": s.name})
					}
				}
				reply(200, map[string]any{"data": out})
			case "POST":
				var b struct {
					ProjectID int    `json:"project_id"`
					Name      string `json:"name"`
				}
				_ = json.NewDecoder(r.Body).Decode(&b)
				t := map[int]string{1: "A", 2: "B"}[b.ProjectID]
				if t == "" || !member(t) || u.role != "admin" {
					reply(403, map[string]string{"error": "forbidden"})
					return
				}
				reply(201, map[string]string{"ok": "created"})
			default:
				reply(405, nil)
			}
			return
		}
		id, _ := strconv.Atoi(segs[3])
		s := f.secrets[id]
		if s == nil {
			reply(404, map[string]string{"error": "not found"})
			return
		}
		switch r.Method {
		case "GET":
			if f.plant == "deadfp" && s.tenant == "B" && u.tenant == "*" {
				reply(403, map[string]string{"error": "owner only"}) // readable by the owner, not by the observer
				return
			}
			if !member(s.tenant) && f.plant != "bola" {
				reply(403, map[string]string{"error": "forbidden"})
				return
			}
			if f.plant == "driftreads" || f.plant == "driftbare" || f.plant == "effectdrift" {
				f.reads++
			}
			key := "total_reads"
			if f.plant == "driftbare" || f.plant == "effectdrift" {
				key = "hits" // not recognised as volatile: calibration must catch it
			}
			reply(200, map[string]any{"name": s.name, "value": s.value, key: f.reads})
		case "PUT":
			okRole := u.role == "admin" || (f.plant == "role" && u.role == "viewer")
			if !member(s.tenant) || !okRole {
				reply(403, map[string]string{"error": "forbidden"})
				return
			}
			var b struct{ Value string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			s.value = "lrcanary-" + strings.ToLower(s.tenant) + "-" + b.Value
			reply(200, map[string]string{"ok": "updated"})
		case "DELETE":
			if !member(s.tenant) || u.role != "admin" {
				if f.plant == "effect" || f.plant == "effectdrift" {
					delete(f.secrets, id) // 403 but executed
				}
				reply(403, map[string]string{"error": "forbidden"})
				return
			}
			delete(f.secrets, id)
			reply(204, nil)
		default:
			reply(405, nil)
		}
		return
	}
	// /api/v1/projects/{id}/secrets
	if len(segs) == 5 && segs[2] == "projects" && segs[4] == "secrets" {
		t := map[string]string{"1": "A", "2": "B"}[segs[3]]
		if authed && !member(t) {
			reply(403, map[string]string{"error": "forbidden"})
			return
		}
		var out []string
		for _, s := range f.secrets {
			if s.tenant == t {
				out = append(out, s.name)
			}
		}
		reply(200, map[string]any{"data": out})
		return
	}
	reply(404, nil)
}

func fakeOps() []Op {
	valueBody := map[string]any{"type": "object", "required": []any{"value"},
		"properties": map[string]any{"value": map[string]any{"type": "string"}}}
	createBody := map[string]any{"type": "object", "required": []any{"project_id", "name"},
		"properties": map[string]any{"project_id": map[string]any{"type": "integer"}, "name": map[string]any{"type": "string"}}}
	return []Op{
		{Method: "GET", Path: "/api/v1/secrets"},
		{Method: "POST", Path: "/api/v1/secrets", Body: createBody},
		{Method: "GET", Path: "/api/v1/secrets/{id}", Params: []Param{{Name: "id", In: "path"}}},
		{Method: "PUT", Path: "/api/v1/secrets/{id}", Body: valueBody},
		{Method: "DELETE", Path: "/api/v1/secrets/{id}"},
		{Method: "GET", Path: "/api/v1/projects/{id}/secrets"},
		{Method: "PUT", Path: "/api/v1/users/{id}", Params: []Param{{Name: "id", In: "path"}}},
	}
}

func fakeWorld(t *testing.T, plant string) *World {
	t.Helper()
	srv := httptest.NewServer(newFakeAPI(plant))
	t.Cleanup(srv.Close)
	w := NewWorld(srv.URL, &Spec{Ops: fakeOps()})
	w.Actors = map[string]*Actor{
		"A":       {Name: "A", Token: "tokA", Tenant: "A", Role: "admin"},
		"V":       {Name: "V", Token: "tokV", Tenant: "A", Role: "viewer"},
		"B":       {Name: "B", Token: "tokB", Tenant: "B", Role: "admin"},
		"N":       {Name: "N", Token: "tokN"},
		"anon":    {Name: "anon", DenyAll: true},
		"garbage": {Name: "garbage", Token: "not-a-token", DenyAll: true},
	}
	w.Attackers = []string{"anon", "garbage", "N", "B", "V", "A"}
	w.Observer = &Actor{Name: "root", Token: "tokRoot"}
	w.AddID("A", "project", "1")
	w.AddID("A", "secret", "1")
	w.AddID("A", "secret", "2")
	w.AddID("B", "project", "2")
	w.AddID("B", "secret", "3")
	w.FPPaths = []string{"/api/v1/secrets/1", "/api/v1/secrets/2", "/api/v1/secrets/3"}
	w.FPTenant = map[string]string{"/api/v1/secrets/1": "A", "/api/v1/secrets/2": "A", "/api/v1/secrets/3": "B"}
	return w
}

func TestSelfTest_CleanFakeHasNoCandidates(t *testing.T) {
	w := fakeWorld(t, "")
	rs := w.Run(Options{})
	if len(rs) < 50 {
		t.Fatalf("replay produced only %d probes; harness is not exercising anything", len(rs))
	}
	if c := Candidates(rs); len(c) != 0 {
		for _, r := range c {
			t.Logf("unexpected candidate: %s %s %s (%s)", r.Class, r.Actor, r.Target, r.Detail)
		}
		t.Fatalf("clean API produced %d candidates", len(c))
	}
	// Non-vacuity: the legitimate actor's controls succeeded.
	ok := 0
	for _, r := range rs {
		if r.Class == ClassControlOK {
			ok++
		}
	}
	if ok < 3 {
		t.Fatalf("only %d positive controls succeeded", ok)
	}
}

func TestSelfTest_PlantedDefectsAreFound(t *testing.T) {
	cases := []struct {
		plant, wantClass, wantOp, wantActor string
	}{
		{"bola", ClassCandStatus, "GET /api/v1/secrets/{id}", "B"},
		{"role", ClassCandStatus, "PUT /api/v1/secrets/{id}", "V"},
		{"noauth", ClassCandStatus, "GET /api/v1/projects/{id}/secrets", "anon"},
		{"effect", ClassCandEffect, "DELETE /api/v1/secrets/{id}", "N"},
		{"leak", ClassCandLeak, "GET /api/v1/secrets", "B"},
		// users are not a tenant kind: without the identity rule these were never judged
		{"userwrite", ClassCandStatus, "PUT /api/v1/users/{id}", "V"},
		{"userwrite", ClassCandStatus, "PUT /api/v1/users/{id}", "N"},
	}
	for _, tc := range cases {
		t.Run(tc.plant, func(t *testing.T) {
			w := fakeWorld(t, tc.plant)
			cands := Candidates(w.Run(Options{}))
			found := false
			for _, r := range cands {
				if r.OpKey != tc.wantOp {
					t.Errorf("candidate on an unplanted op: %s %s %s (%s)", r.Class, r.OpKey, r.Actor, r.Detail)
				}
				if strings.Contains(r.Class, strings.TrimPrefix(tc.wantClass, "CANDIDATE-")) && r.Actor == tc.wantActor {
					found = true
				}
			}
			if !found {
				for _, r := range cands {
					t.Logf("candidate: %s %s %s %s %s (%s)", r.Class, r.Variant, r.Actor, r.Method, r.Target, r.Detail)
				}
				t.Fatalf("planted %q defect not reported as %s by %s on %s; candidates=%d", tc.plant, tc.wantClass, tc.wantActor, tc.wantOp, len(cands))
			}
		})
	}
}

// Oracle noise: a GET that bumps a read counter must not make every denied
// request look like a state change. With the counter key recognised as
// volatile the run is silent; with an unrecognised key name the quiescence
// calibration must detect and mask the drift, and say so.
func TestSelfTest_ObserverReadDriftIsNotAnEffect(t *testing.T) {
	for _, plant := range []string{"driftreads"} {
		w := fakeWorld(t, plant)
		rs := w.Run(Options{})
		if c := Candidates(rs); len(c) != 0 {
			for _, r := range c {
				t.Logf("candidate: %s %s %s %s (%s)", r.Class, r.Actor, r.Method, r.Target, r.Detail)
			}
			t.Fatalf("%s: %d candidates from observer-induced drift", plant, len(c))
		}
	}
}

func TestSelfTest_UnknownDriftKeyIsCalibratedAway(t *testing.T) {
	w := fakeWorld(t, "driftbare")
	rs := w.Run(Options{})
	if len(w.DriftFound) == 0 {
		t.Fatalf("calibration did not notice a self-drifting path")
	}
	if c := Candidates(rs); len(c) != 0 {
		t.Fatalf("drifting path still produced %d candidates", len(c))
	}
}

// A handler that mutates state on a 403 must still be flagged when the read
// path also drifts: masking drift may not hide a real effect.
func TestSelfTest_EffectOn403StillFoundAmidDrift(t *testing.T) {
	w := fakeWorld(t, "effectdrift")
	cands := Candidates(w.Run(Options{}))
	found := false
	for _, r := range cands {
		if r.OpKey != "DELETE /api/v1/secrets/{id}" {
			t.Errorf("candidate on unplanted op: %s %s %s", r.Class, r.OpKey, r.Detail)
		}
		if r.Class == ClassCandEffect && r.Status == 403 {
			found = true
		}
	}
	if !found {
		t.Fatalf("403-but-executed delete not flagged amid drift; candidates=%d", len(cands))
	}
}

// The model has no opinion on self-service routes, and the positive control is
// skipped exactly for operations that change who may do what.
func TestModel_SelfServiceAndAuthorityChanging(t *testing.T) {
	viewer := &Actor{Name: "V", Tenant: "A", Role: "viewer"}
	for _, op := range []Op{
		{Method: "POST", Path: "/api/v1/secret-access-requests"},
		{Method: "DELETE", Path: "/api/v1/secrets/{id}/self-share"},
	} {
		if got := Expect(viewer, op, "A"); got != Unknown {
			t.Errorf("%s %s: verdict %v, want unknown", op.Method, op.Path, got)
		}
	}
	if got := Expect(viewer, Op{Method: "PUT", Path: "/api/v1/secrets/{id}"}, "A"); got != Deny {
		t.Errorf("viewer PUT secret: verdict %v, want deny", got)
	}
	for path, want := range map[string]bool{
		"/api/v1/projects/{id}/machine-identities/{mid}/roles": true,
		"/api/v1/projects/{id}/members":                        true,
		"/api/v1/secrets/{id}":                                 false,
		"/api/v1/projects/{id}":                                false,
	} {
		if got := authorityChanging(Op{Method: "POST", Path: path}); got != want {
			t.Errorf("authorityChanging(POST %s) = %v, want %v", path, got, want)
		}
	}
	if authorityChanging(Op{Method: "GET", Path: "/api/v1/projects/{id}/members"}) {
		t.Error("a GET never changes authority")
	}
}

// Writes to one user or role by an actor with no authority are judged even
// though the ids are install-wide, not tenant-owned.
func TestModel_IdentityWritesAreDeniedForViewerAndNoGrant(t *testing.T) {
	viewer := &Actor{Name: "V", Tenant: "A", Role: "viewer"}
	none := &Actor{Name: "N"}
	admin := &Actor{Name: "A", Tenant: "A", Role: "admin"}
	for _, op := range []Op{
		{Method: "PUT", Path: "/api/v1/users/{id}"},
		{Method: "DELETE", Path: "/api/v1/users/{id}"},
		{Method: "POST", Path: "/api/v1/users/{id}/suspend"},
		{Method: "POST", Path: "/api/v1/users/{id}/revoke-sessions"},
		{Method: "POST", Path: "/api/v1/users/{id}/reissue-one-time-password"},
		{Method: "PUT", Path: "/api/v1/roles/{id}"},
		{Method: "DELETE", Path: "/api/v1/roles/{id}"},
		{Method: "POST", Path: "/api/v1/roles/{id}/permissions"},
	} {
		for _, a := range []*Actor{viewer, none} {
			if got := Expect(a, op, ""); got != Deny {
				t.Errorf("%s %s %s: verdict %v, want deny", a.Name, op.Method, op.Path, got)
			}
		}
		if got := Expect(admin, op, ""); got != Unknown {
			t.Errorf("project admin %s %s: verdict %v, want unknown (ceiling rules not modelled)", op.Method, op.Path, got)
		}
	}
	for _, op := range []Op{
		{Method: "GET", Path: "/api/v1/users/{id}"},
		{Method: "GET", Path: "/api/v1/roles/by-name"},
		{Method: "POST", Path: "/api/v1/users"},
	} {
		if identityMutation(op) {
			t.Errorf("%s %s is not a write to one user or role", op.Method, op.Path)
		}
	}
}

// A response that carries a different marked name than the request sent is a
// leak even when the request itself carried the marker prefix.
func TestLeakOracle_ComparesNamesNotThePrefix(t *testing.T) {
	w := NewWorld("http://unused.invalid", &Spec{})
	b := &Actor{Name: "B", Tenant: "B", Role: "admin"}
	p := Probe{Method: "GET", Target: "/api/v1/secrets/value?ref=lrcanary-a-proj%2Fdevelopment%2Flrcanary-a-secret-1"}
	if got := w.leaked(b, p, []byte(`{"error":"no access to lrcanary-a-proj/development/lrcanary-a-secret-1."}`)); got != "" {
		t.Errorf("echo of the requested name reported as a leak: %s", got)
	}
	if got := w.leaked(b, p, []byte(`{"data":[{"name":"lrcanary-a-secret-1"},{"name":"lrcanary-a-secret-2"}]}`)); got == "" {
		t.Error("a second tenant-A name in the response was excused by the request's prefix")
	}
	if got := w.leaked(&Actor{Name: "A", Tenant: "A", Role: "admin"}, p, []byte(`lrcanary-a-secret-2`)); got != "" {
		t.Errorf("own tenant's names are not a leak: %s", got)
	}
}

// A fingerprint path that never answers 2xx makes the effect oracle blind; the
// run must say so. Reading it as its owner fixes it.
func TestSelfTest_DeadFingerprintPathIsReported(t *testing.T) {
	w := fakeWorld(t, "deadfp")
	dead := w.DeadFingerprintPaths()
	if len(dead) != 1 || !strings.Contains(dead[0], "/api/v1/secrets/3") {
		t.Fatalf("dead paths = %v, want only /api/v1/secrets/3", dead)
	}
	w.FPReader["/api/v1/secrets/3"] = w.Actors["B"]
	if dead := w.DeadFingerprintPaths(); len(dead) != 0 {
		t.Fatalf("owner read still dead: %v", dead)
	}
	w2 := fakeWorld(t, "deadfp")
	w2.Run(Options{Only: "/api/v1/secrets/{id}"})
	if len(w2.DeadBefore) == 0 || len(w2.DeadAfter) == 0 {
		t.Fatalf("Run did not record dead paths: before=%v after=%v", w2.DeadBefore, w2.DeadAfter)
	}
}

// A server that goes away must leave a trace: transport errors are counted.
func TestSelfTest_TransportErrorsAreCounted(t *testing.T) {
	srv := httptest.NewServer(newFakeAPI(""))
	w := NewWorld(srv.URL, &Spec{Ops: fakeOps()})
	w.Observer = &Actor{Name: "root", Token: "tokRoot"}
	w.Actors["root"] = w.Observer
	if _, _, err := w.Do(w.Observer, "GET", "/api/v1/secrets/1", nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := w.TransportErrors(); n != 0 {
		t.Fatalf("%d transport errors on a healthy server", n)
	}
	srv.Close()
	r := w.exec(Probe{Actor: "root", Method: "GET", Target: "/api/v1/secrets/1"}, Op{Method: "GET", Path: "/api/v1/secrets/{id}"})
	if r.Class != ClassInconclusive {
		t.Errorf("class = %s", r.Class)
	}
	if n, last := w.TransportErrors(); n == 0 || last == "" {
		t.Fatalf("transport error not recorded: %d %q", n, last)
	}
}

// Mutated-id probes must not be aimed at the actor's own fixtures.
func TestOwnedByActor(t *testing.T) {
	w := fakeWorld(t, "")
	a := &Actor{Name: "A", Tenant: "A", Role: "admin"}
	del := Op{Method: "DELETE", Path: "/api/v1/secrets/{id}"}
	if !w.ownedByActor(a, del, "/api/v1/secrets/2") {
		t.Error("secret 2 is tenant A's own")
	}
	if w.ownedByActor(a, del, "/api/v1/secrets/3") {
		t.Error("secret 3 is tenant B's: a legitimate attack target")
	}
	if w.ownedByActor(a, Op{Method: "GET", Path: "/api/v1/secrets/{id}"}, "/api/v1/secrets/2") {
		t.Error("reads are always sent")
	}
}

// The volatile-key filter drops only what moves on its own, and says what it dropped.
func TestStable_NarrowAndReports(t *testing.T) {
	dropped := map[string]bool{}
	in := map[string]any{
		"total_reads": 3, "last_login_at": "x", "expires_at": "2030", "created_by": "u1",
		"account_id": 7, "checksum": "abc", "updated_at": "t", "name": "n",
	}
	out := stable(in, dropped).(map[string]any)
	for _, k := range []string{"expires_at", "created_by", "account_id", "checksum", "updated_at", "name"} {
		if _, ok := out[k]; !ok {
			t.Errorf("%s was dropped; it is state", k)
		}
	}
	if !dropped["total_reads"] || !dropped["last_login_at"] || len(dropped) != 2 {
		t.Errorf("dropped = %v", dropped)
	}
}
