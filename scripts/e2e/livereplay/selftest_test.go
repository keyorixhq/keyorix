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
			if !member(s.tenant) && f.plant != "bola" {
				reply(403, map[string]string{"error": "forbidden"})
				return
			}
			reply(200, map[string]string{"name": s.name, "value": s.value})
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
				if f.plant == "effect" {
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
