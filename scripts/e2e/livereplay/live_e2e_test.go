//go:build e2e

package livereplay

// Live driver: boots a throwaway keyorix-server (fresh temp dir, SQLite, synthetic
// data), seeds two tenants, records actor A's legitimate session, and replays it
// (see replay.go). Opt-in:
//
//	go test -tags e2e ./scripts/e2e/livereplay/ -run TestLiveReplay -v -timeout 40m
//
// Knobs (environment):
//
//	LIVEREPLAY_OUT      directory for results.jsonl and candidates.txt (default: a temp dir)
//	LIVEREPLAY_REPEAT   number of fresh-server runs; candidates must recur in all of them (default 1)
//	LIVEREPLAY_ONLY     only operations whose key contains this substring
//
// The rate limiter is switched off in the generated config (a 50 req/s per-principal
// limit would only slow the replay; authorization is not what it protects) and
// require_mfa is switched off so the actors can be logged in with a password. Both
// are recorded in the run header.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

func TestMain(m *testing.M) { os.Exit(harness.RunMain(m)) }

const pw = "Amber-Heron-41-Delta!"

func buildServer(t *testing.T, root, out string, overlay map[string]string) {
	t.Helper()
	args := []string{"build", "-o", out}
	if len(overlay) > 0 {
		repl := map[string]string{}
		for target, content := range overlay {
			tmp := filepath.Join(filepath.Dir(out), "overlay-"+filepath.Base(target))
			if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			repl[filepath.Join(root, target)] = tmp
		}
		raw, _ := json.Marshal(map[string]any{"Replace": repl})
		ov := filepath.Join(filepath.Dir(out), "overlay.json")
		if err := os.WriteFile(ov, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-overlay", ov)
	}
	args = append(args, "./server")
	cmd := exec.Command("go", args...) // #nosec G204 -- fixed arguments, test tooling
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
}

// bootThrowaway runs the operator bootstrap sequence the harness documents, with
// the two config switches described above.
func bootThrowaway(t *testing.T, binary string) (*harness.Server, string) {
	t.Helper()
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir), "KEYORIX_MASTER_PASSWORD=livereplay-throwaway-master-password")
	run := func(args ...string) {
		t.Helper()
		if out, err := harness.RunAdminCmd(binary, dir, env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	cfg := "./keyorix.yaml"
	run("init", "--dev", "--config", cfg)
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "\n  require_mfa: true\n") {
		t.Fatal("generated config lacks require_mfa: true")
	}
	text = strings.Replace(text, "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)
	i := strings.Index(text, "ratelimit:")
	if i < 0 {
		t.Fatal("no ratelimit key in generated config")
	}
	j := strings.Index(text[i:], "enabled: true")
	if j < 0 {
		t.Fatal("ratelimit.enabled not true in generated config")
	}
	text = text[:i+j] + "enabled: false" + text[i+j+len("enabled: true"):]
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil { // #nosec G306,G703 -- t.TempDir()
		t.Fatal(err)
	}
	run("encryption", "init", "--config", cfg)
	run("migrate", "--config", cfg)
	port := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, port)
	s := harness.BootAndBootstrap(t, binary, dir, env, cfg, port, "livereplay-bootstrap-token-0123456789",
		"lr-root", "lr-root@example.invalid", harness.BootstrapAdminPassword)
	t.Cleanup(s.Close)
	return s, harness.BootstrapAdminPassword
}

// ---- tiny JSON helpers over the envelope {"success":..,"data":{..}} ----

func jparse(b []byte) any {
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

// findID returns the first "id" found in the response data (data.id, data.<obj>.id).
func findID(b []byte) string {
	m, _ := jparse(b).(map[string]any)
	d, _ := m["data"].(map[string]any)
	if d == nil {
		return ""
	}
	if s := scalar(d["id"]); s != "" {
		return s
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if sub, ok := d[k].(map[string]any); ok {
			if s := scalar(sub["id"]); s != "" {
				return s
			}
		}
	}
	return ""
}

// findStr returns the first string value under any of keys, searching data and one level below.
func findStr(b []byte, keys ...string) string {
	m, _ := jparse(b).(map[string]any)
	d, _ := m["data"].(map[string]any)
	if d == nil {
		return ""
	}
	var look func(mm map[string]any, depth int) string
	look = func(mm map[string]any, depth int) string {
		for _, k := range keys {
			if s, ok := mm[k].(string); ok && s != "" {
				return s
			}
		}
		if depth == 0 {
			return ""
		}
		for _, v := range mm {
			if sub, ok := v.(map[string]any); ok {
				if s := look(sub, depth-1); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return look(d, 2)
}

// findIDByName finds the id of the element named name in a list response.
func findIDByName(b []byte, name string) string {
	var out string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if n, _ := t["name"].(string); n == name {
				if s := scalar(t["id"]); s != "" && out == "" {
					out = s
				}
			}
			for _, x := range t {
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(jparse(b))
	return out
}

func scalar(v any) string {
	switch t := v.(type) {
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case string:
		return t
	}
	return ""
}

// ---- world construction ----

type seeder struct {
	t *testing.T
	w *World
}

func (s *seeder) call(a *Actor, method, path string, body any, want ...int) []byte {
	s.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	status, resp, err := s.w.Do(a, method, path, raw)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	ok := status >= 200 && status < 300
	if len(want) > 0 {
		ok = false
		for _, x := range want {
			ok = ok || x == status
		}
	}
	if !ok {
		s.t.Fatalf("seed %s %s as %s: HTTP %d: %.300s", method, path, a.Name, status, resp)
	}
	return resp
}

// record runs a legitimate-session request as A and keeps it for replay.
func (s *seeder) record(a *Actor, method, path string, body any) []byte {
	s.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	status, resp, err := s.w.Record(a, method, path, raw)
	if err != nil {
		s.t.Fatalf("record %s %s: %v", method, path, err)
	}
	if status < 200 || status >= 300 {
		s.t.Logf("recorded session: %s %s as %s -> %d (kept for replay): %.160s", method, path, a.Name, status, resp)
	}
	return resp
}

func (s *seeder) login(name, user, password string) *Actor {
	s.t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": password})
	status, resp, err := s.w.Do(&Actor{}, "POST", "/auth/login", b)
	if err != nil || status != 200 {
		s.t.Fatalf("login %s: %d %v %.200s", user, status, err, resp)
	}
	tok := findStr(resp, "token")
	if tok == "" {
		s.t.Fatalf("login %s: no token in %.200s", user, resp)
	}
	return &Actor{Name: name, Token: tok}
}

func buildWorld(t *testing.T, srv *harness.Server, rootPW string) *World {
	t.Helper()
	spec, err := LoadSpec(filepath.Join(harness.RepoRoot(t), "server/http/handlers/openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	w := NewWorld(srv.BaseURL, spec)
	s := &seeder{t: t, w: w}
	root := s.login("root", "lr-root", rootPW)
	w.Observer = root

	// projects + environments
	mkProject := func(tenant, name string) {
		b := s.call(root, "POST", "/api/v1/projects", map[string]any{"name": name, "description": name + " description"})
		pid := findID(b)
		if pid == "" {
			t.Fatalf("project %s: no id in %.200s", name, b)
		}
		w.AddID(tenant, "project", pid)
		eb := s.call(root, "GET", "/api/v1/projects/"+pid+"/environments", nil)
		var envName string
		for _, n := range []string{"development", "staging", "production"} {
			if id := findIDByName(eb, n); id != "" {
				w.AddID(tenant, "env", id)
				if envName == "" {
					envName = n
				}
			}
		}
		if envName == "" {
			t.Fatalf("project %s: no environments in %.300s", name, eb)
		}
		w.Refs[tenant] = name + "/" + envName + "/" + w.Marker[tenant] + "secret-1"
	}
	mkProject("A", "lrcanary-a-proj")
	mkProject("B", "lrcanary-b-proj")

	// users (names carry no canary marker: usernames are install-wide directory data)
	mkUser := func(name string) string {
		b := s.call(root, "POST", "/api/v1/users", map[string]any{
			"username": name, "email": name + "@example.invalid", "display_name": "LR " + strings.ToUpper(name[:1]) + name[1:], "password": pw,
		})
		id := findID(b)
		if id == "" {
			t.Fatalf("user %s: no id in %.200s", name, b)
		}
		return id
	}
	uid := map[string]string{}
	for _, n := range []string{"alpha", "vivian", "bravo", "nobody", "victima", "victimb"} {
		uid[n] = mkUser(n)
	}
	w.AddID("A", "user", uid["victima"])
	w.AddID("B", "user", uid["victimb"])

	roleID := func(name string) string {
		b := s.call(root, "GET", "/api/v1/roles/by-name?name="+name, nil)
		id := findID(b)
		if id == "" {
			t.Fatalf("role %s: %.200s", name, b)
		}
		return id
	}
	pAdmin, pViewer, pDev := roleID("project_admin"), roleID("project_viewer"), roleID("project_developer")
	w.AddID("A", "role", pViewer)
	grant := func(user, role, tenant string) {
		pid, _ := w.FirstID(tenant, "project")
		pn, _ := strconv.Atoi(pid)
		un, _ := strconv.Atoi(uid[user])
		rn, _ := strconv.Atoi(role)
		s.call(root, "POST", "/api/v1/user-roles", map[string]any{"user_id": un, "role_id": rn, "project_id": pn})
	}
	grant("alpha", pAdmin, "A")
	grant("vivian", pViewer, "A")
	grant("bravo", pAdmin, "B")
	grant("victima", pViewer, "A")
	grant("victimb", pViewer, "B")

	A := s.login("A", "alpha", pw)
	A.Tenant, A.Role = "A", "admin"
	V := s.login("V", "vivian", pw)
	V.Tenant, V.Role = "A", "viewer"
	B := s.login("B", "bravo", pw)
	B.Tenant, B.Role = "B", "admin"
	N := s.login("N", "nobody", pw)
	w.Actors = map[string]*Actor{"A": A, "V": V, "B": B, "N": N}

	// secrets: tenant B by root; tenant A through A's own recorded session
	aProj, _ := w.FirstID("A", "project")
	aEnv, _ := w.FirstID("A", "env")
	bProj, _ := w.FirstID("B", "project")
	bEnv, _ := w.FirstID("B", "env")
	pn := func(x string) int { n, _ := strconv.Atoi(x); return n }
	mkSecret := func(by *Actor, tenant, proj, env, name, value string, record bool) string {
		body := map[string]any{"name": name, "project_id": pn(proj), "environment_id": pn(env), "value": value, "type": "generic", "description": name + " note"}
		var b []byte
		if record {
			b = s.record(by, "POST", "/api/v1/secrets", body)
		} else {
			b = s.call(by, "POST", "/api/v1/secrets", body)
		}
		id := findID(b)
		if id == "" {
			t.Fatalf("secret %s: no id in %.200s", name, b)
		}
		w.AddID(tenant, "secret", id)
		return id
	}
	a1 := mkSecret(A, "A", aProj, aEnv, "lrcanary-a-secret-1", "LRCANARY-A-VALUE-1", true)
	mkSecret(A, "A", aProj, aEnv, "lrcanary-a-secret-2", "LRCANARY-A-VALUE-2", true)
	b1 := mkSecret(B, "B", bProj, bEnv, "lrcanary-b-secret-1", "LRCANARY-B-VALUE-1", false)
	mkSecret(B, "B", bProj, bEnv, "lrcanary-b-secret-2", "LRCANARY-B-VALUE-2", false)

	// A's legitimate session: reads, updates, shares, machine identity, tokens, ACL, group, invitation
	s.record(A, "GET", "/api/v1/projects", nil)
	s.record(A, "GET", "/api/v1/projects/"+aProj, nil)
	s.record(A, "GET", "/api/v1/secrets?project_id="+aProj, nil)
	s.record(A, "GET", "/api/v1/secrets/"+a1, nil)
	s.record(A, "GET", "/api/v1/secrets/value?ref="+w.Refs["A"], nil)
	s.record(A, "PUT", "/api/v1/secrets/"+a1, map[string]any{"value": "LRCANARY-A-VALUE-1b"})
	s.record(A, "GET", "/api/v1/secrets/"+a1+"/versions", nil)
	sb := s.record(A, "POST", "/api/v1/secrets/"+a1+"/share", map[string]any{"recipient_id": pn(uid["vivian"]), "permission": "read"})
	if id := findID(sb); id != "" {
		w.AddID("A", "share", id)
	}
	s.record(A, "GET", "/api/v1/secrets/"+a1+"/shares", nil)
	ab := s.record(A, "POST", "/api/v1/secrets/"+a1+"/acl", map[string]any{"user_id": pn(uid["victima"]), "permissions": []string{"secrets.read"}})
	if id := findID(ab); id != "" {
		w.AddID("A", "acl", id)
	}
	s.call(B, "POST", "/api/v1/secrets/"+b1+"/share", map[string]any{"recipient_id": pn(uid["victimb"]), "permission": "read"})
	mb := s.record(A, "POST", "/api/v1/projects/"+aProj+"/machine-identities", map[string]any{"name": "lrcanary-a-machine", "description": "lrcanary-a machine"})
	mA := findID(mb)
	if mA == "" {
		s.t.Logf("A could not create a machine identity (%.160s); seeding as root", mb)
		mA = findID(s.call(root, "POST", "/api/v1/projects/"+aProj+"/machine-identities", map[string]any{"name": "lrcanary-a-machine"}))
	}
	w.AddID("A", "machine", mA)
	s.call(root, "POST", "/api/v1/projects/"+aProj+"/machine-identities/"+mA+"/roles", map[string]any{"role_id": pn(pViewer)})
	mtA := s.call(root, "POST", "/api/v1/projects/"+aProj+"/machine-identities/"+mA+"/tokens", map[string]any{"name": "lrcanary-a-mtoken"})
	w.AddID("A", "machinetoken", findID(mtA))
	mB := findID(s.call(root, "POST", "/api/v1/projects/"+bProj+"/machine-identities", map[string]any{"name": "lrcanary-b-machine"}))
	w.AddID("B", "machine", mB)
	s.call(root, "POST", "/api/v1/projects/"+bProj+"/machine-identities/"+mB+"/roles", map[string]any{"role_id": pn(pDev)})
	mtB := s.call(root, "POST", "/api/v1/projects/"+bProj+"/machine-identities/"+mB+"/tokens", map[string]any{"name": "lrcanary-b-mtoken"})
	w.AddID("B", "machinetoken", findID(mtB))
	// a token to revoke
	mtR := s.call(root, "POST", "/api/v1/projects/"+aProj+"/machine-identities/"+mA+"/tokens", map[string]any{"name": "lrcanary-a-revoked"})
	revokedMachine := findStr(mtR, "token", "raw_token", "value")
	s.call(root, "DELETE", "/api/v1/projects/"+aProj+"/machine-identities/"+mA+"/tokens/"+findID(mtR), nil)
	w.Actors["MA"] = &Actor{Name: "MA", Token: findStr(mtA, "token", "raw_token", "value"), Tenant: "A", Role: "viewer", Machine: true}
	w.Actors["MB"] = &Actor{Name: "MB", Token: findStr(mtB, "token", "raw_token", "value"), Tenant: "B", Role: "admin", Machine: true}
	w.Actors["revokedmachine"] = &Actor{Name: "revokedmachine", Token: revokedMachine, DenyAll: true}

	gb := s.record(A, "POST", "/api/v1/groups", map[string]any{"name": "lrcanary-a-group", "description": "lrcanary-a"})
	if id := findID(gb); id != "" {
		w.AddID("A", "group", id)
		s.call(root, "POST", "/api/v1/groups/"+id+"/members", map[string]any{"user_id": pn(uid["victima"])})
	}
	gbb := s.call(root, "POST", "/api/v1/groups", map[string]any{"name": "lrcanary-b-group", "description": "lrcanary-b"})
	if id := findID(gbb); id != "" {
		w.AddID("B", "group", id)
		s.call(root, "POST", "/api/v1/groups/"+id+"/members", map[string]any{"user_id": pn(uid["victimb"])})
	}
	ib := s.record(A, "POST", "/api/v1/projects/"+aProj+"/invitations", map[string]any{"email": "lr-invitee-a@example.invalid", "role": "project_viewer"})
	if id := findID(ib); id != "" {
		w.AddID("A", "invitation", id)
	}
	pb := s.record(A, "POST", "/api/v1/auth/tokens", map[string]any{"name": "lrcanary-a-pat"})
	if id := findID(pb); id != "" {
		w.AddID("A", "pat", id)
	}

	// credential variants that must be refused everywhere
	rp := s.call(A, "POST", "/api/v1/auth/tokens", map[string]any{"name": "lrcanary-a-revokedpat"})
	revokedPAT := findStr(rp, "token", "raw_token", "value")
	s.call(A, "DELETE", "/api/v1/auth/tokens/"+findID(rp), nil)
	ep := s.call(A, "POST", "/api/v1/auth/tokens", map[string]any{"name": "lrcanary-a-expiringpat", "expires_at": time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)})
	expiredPAT := findStr(ep, "token", "raw_token", "value")
	lo := s.login("loggedout", "alpha", pw)
	s.call(lo, "POST", "/auth/logout", nil, 200, 204)
	tampered := A.Token
	if n := len(tampered); n > 4 {
		c := byte('A')
		if tampered[n-2] == 'A' {
			c = 'B'
		}
		tampered = tampered[:n-2] + string(c) + tampered[n-1:]
	}
	w.Actors["anon"] = &Actor{Name: "anon", DenyAll: true}
	w.Actors["garbage"] = &Actor{Name: "garbage", Token: "kx_not_a_real_token_0123456789abcdef", DenyAll: true}
	w.Actors["tampered"] = &Actor{Name: "tampered", Token: tampered, DenyAll: true}
	w.Actors["loggedout"] = &Actor{Name: "loggedout", Token: lo.Token, DenyAll: true}
	w.Actors["revokedpat"] = &Actor{Name: "revokedpat", Token: revokedPAT, DenyAll: true}
	w.Actors["expiredpat"] = &Actor{Name: "expiredpat", Token: expiredPAT, DenyAll: true}
	time.Sleep(3 * time.Second)
	w.Attackers = []string{"anon", "garbage", "tampered", "loggedout", "revokedpat", "revokedmachine", "expiredpat", "N", "B", "MB", "MA", "V", "A"}

	// state fingerprint (read by the observer only)
	w.FPTenant = map[string]string{}
	fp := func(tenant, path string) {
		w.FPPaths = append(w.FPPaths, path)
		w.FPTenant[path] = tenant
	}
	for _, tn := range []string{"A", "B"} {
		p, _ := w.FirstID(tn, "project")
		fp(tn, "/api/v1/projects/"+p)
		fp(tn, "/api/v1/secrets?project_id="+p)
		fp(tn, "/api/v1/projects/"+p+"/machine-identities")
		fp(tn, "/api/v1/projects/"+p+"/members")
		fp(tn, "/api/v1/projects/"+p+"/environments")
		for _, sid := range w.IDs[tn]["secret"] {
			fp(tn, "/api/v1/secrets/"+sid)
			fp(tn, "/api/v1/secrets/"+sid+"/versions")
			fp(tn, "/api/v1/secrets/"+sid+"/shares")
			fp(tn, "/api/v1/secrets/"+sid+"/acl")
		}
		fp(tn, "/api/v1/secrets/value?ref="+w.Refs[tn])
		if g, ok := w.FirstID(tn, "group"); ok {
			fp(tn, "/api/v1/groups/"+g+"/members")
		}
		if u, ok := w.FirstID(tn, "user"); ok {
			fp(tn, "/api/v1/users/"+u+"/roles")
		}
	}
	for _, n := range []string{"alpha", "vivian", "bravo", "nobody"} {
		fp("", "/api/v1/users/"+uid[n]+"/roles")
	}
	fp("", "/api/v1/groups")
	return w
}

// ---- runs ----

func outDir(t *testing.T) string {
	if d := os.Getenv("LIVEREPLAY_OUT"); d != "" {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		return d
	}
	return t.TempDir()
}

type runStats struct {
	Probes, Controls, ControlOK int
	Ops                         int
	Conclusive                  map[string]bool
	Cands                       []Result
	Summary                     map[string]int
}

func runOnce(t *testing.T, binary, sink string) runStats {
	t.Helper()
	srv, rootPW := bootThrowaway(t, binary)
	w := buildWorld(t, srv, rootPW)
	f, err := os.Create(sink) // #nosec G304 -- operator-chosen output path
	if err != nil {
		t.Fatal(err)
	}
	bw := bufio.NewWriter(f)
	enc := json.NewEncoder(bw)
	st := runStats{Conclusive: map[string]bool{}}
	rs := w.Run(Options{Only: os.Getenv("LIVEREPLAY_ONLY"), Log: func(r Result) {
		rec := map[string]any{"variant": r.Variant, "actor": r.Actor, "op": r.OpKey, "method": r.Method, "target": r.Target,
			"obj": r.ObjTenant, "verdict": r.Verdict.String(), "status": r.Status, "class": r.Class, "detail": r.Detail, "desc": r.Desc}
		if r.IsCandidate() || r.Class == ClassServerError {
			rec["req"], rec["resp"] = string(r.Body), r.Resp
		}
		_ = enc.Encode(rec)
	}})
	_ = bw.Flush()
	_ = f.Close()
	// keep the server's own log beside the results: panics and unhandled
	// errors behind a 5xx are read from it
	if lb, err := os.ReadFile(srv.LogPath); err == nil { // #nosec G304 -- harness temp path
		_ = os.WriteFile(sink+".server.log", lb, 0o600) // #nosec G306 -- operator-chosen output path
	}
	for _, r := range rs {
		switch {
		case strings.HasPrefix(r.Class, "control"):
			st.Controls++
			if r.Class == ClassControlOK {
				st.ControlOK++
			}
		default:
			st.Probes++
			if r.Status != 0 && r.Status != 400 && r.Status != 422 && r.Status != 429 {
				st.Conclusive[r.OpKey] = true
			}
		}
	}
	st.Cands = Candidates(rs)
	st.Summary = Summary(rs)
	for _, op := range w.Spec.Ops {
		if strings.HasPrefix(op.Path, "/api/v1/") {
			st.Ops++
		}
	}
	t.Logf("server throttled %d requests", w.Throttled)
	return st
}

func writeCandidates(t *testing.T, path string, cands []Result) {
	var sb strings.Builder
	for _, r := range cands {
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s %s\tstatus=%d\tverdict=%s\t%s\n", r.Class, r.Variant, r.Actor, r.Method, r.Target, r.Status, r.Verdict, r.Detail)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil { // #nosec G306 -- operator-chosen output path
		t.Fatal(err)
	}
}

func TestLiveReplay(t *testing.T) {
	root := harness.RepoRoot(t)
	bin := filepath.Join(t.TempDir(), "keyorix-server")
	buildServer(t, root, bin, nil)
	out := outDir(t)
	repeat := 1
	if n, err := strconv.Atoi(os.Getenv("LIVEREPLAY_REPEAT")); err == nil && n > 0 {
		repeat = n
	}
	var stable map[string]Result
	for i := 1; i <= repeat; i++ {
		st := runOnce(t, bin, filepath.Join(out, fmt.Sprintf("results-run%d.jsonl", i)))
		writeCandidates(t, filepath.Join(out, fmt.Sprintf("candidates-run%d.tsv", i)), st.Cands)
		keys := map[string]Result{}
		for _, c := range st.Cands {
			keys[c.Key()] = c
		}
		if stable == nil {
			stable = keys
		} else {
			for k := range stable {
				if _, ok := keys[k]; !ok {
					delete(stable, k)
				}
			}
		}
		t.Logf("run %d: probes=%d controls=%d (ok %d) candidates=%d conclusive-ops=%d/%d", i, st.Probes, st.Controls, st.ControlOK, len(st.Cands), len(st.Conclusive), st.Ops)
		var sk []string
		for k, v := range st.Summary {
			sk = append(sk, fmt.Sprintf("%s=%d", k, v))
		}
		sort.Strings(sk)
		t.Logf("summary: %s", strings.Join(sk, " "))
		// R1: baseline completeness.
		if st.Probes < 2000 || st.ControlOK < 25 {
			t.Errorf("R1 not met: probes=%d (need 2000), positive controls ok=%d (need 25)", st.Probes, st.ControlOK)
		}
	}
	var sc []Result
	for _, v := range stable {
		sc = append(sc, v)
	}
	sort.Slice(sc, func(i, j int) bool { return sc[i].Key() < sc[j].Key() })
	writeCandidates(t, filepath.Join(out, "candidates-stable.tsv"), sc)
	t.Logf("%d candidate(s) recurred in all %d run(s); see %s", len(sc), repeat, out)
	if os.Getenv("LIVEREPLAY_STRICT") == "1" && len(sc) > 0 {
		t.Errorf("%d stable candidate(s)", len(sc))
	}
}

// ---- level-2 planted defects: the real server, built from a source overlay ----

type plant struct {
	name, file string
	edits      [][2]string
	// detected reports whether the candidate list shows the planted defect.
	detected func(r Result) bool
}

var plants = []plant{
	{
		name: "cross-tenant secret authorization (any-scope instead of the secret's scope)",
		file: "internal/core/authz.go",
		edits: [][2]string{{
			"\tallowed, err := c.Authorize(ctx, userID, perm, scope)\n\tif err != nil || allowed {\n\t\tif err == nil {\n\t\t\tnoteGateReadAllow",
			"\tallowed, err := c.HoldsPermissionInAnyScope(ctx, \"user\", userID, perm)\n\tif err != nil || allowed {\n\t\tif err == nil {\n\t\t\tnoteGateReadAllow"}},
		detected: func(r Result) bool {
			return r.Actor == "B" && r.Variant == "swap" && strings.HasPrefix(r.OpKey, "GET /api/v1/secrets/{id}") && r.IsCandidate()
		},
	},
	{
		name: "lower role may write secrets (viewer gets secrets.write)",
		file: "internal/core/authz.go",
		edits: [][2]string{{
			"\tif r.BypassesPermissionChecks {\n\t\treturn true, nil\n\t}\n\treturn r.HasPermission, nil\n}\n\n// Authorize reports",
			"\tif r.BypassesPermissionChecks {\n\t\treturn true, nil\n\t}\n\treturn r.HasPermission || (permission == permSecretsWrite && scope.ProjectID != 0), nil\n}\n\n// Authorize reports"}},
		detected: func(r Result) bool {
			return r.Actor == "V" && r.Variant == "swap" && r.Method == "PUT" && strings.HasPrefix(r.OpKey, "PUT /api/v1/secrets/{id}") && r.IsCandidate()
		},
	},
	{
		name: "revoked PAT and revoked machine token still validate",
		file: "internal/core/pat.go",
		edits: [][2]string{{
			"\tif pat.Revoked {\n\t\treturn nil, nil, nil, 0, ErrPATRevoked",
			"\tif false && pat.Revoked {\n\t\treturn nil, nil, nil, 0, ErrPATRevoked"}},
		detected: func(r Result) bool {
			return r.Actor == "revokedpat" && r.Variant == "swap" && r.IsCandidate()
		},
	},
}

func applyPlant(t *testing.T, root string, p plant) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, p.file)) // #nosec G304 -- repo file
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, e := range p.edits {
		if strings.Count(text, e[0]) != 1 {
			t.Fatalf("plant %q: anchor matches %d times in %s (source moved; update the plant): %q", p.name, strings.Count(text, e[0]), p.file, e[0])
		}
		text = strings.Replace(text, e[0], e[1], 1)
	}
	return map[string]string{p.file: text}
}

func TestLiveReplay_PlantedDefects(t *testing.T) {
	root := harness.RepoRoot(t)
	out := outDir(t)
	for i, p := range plants {
		p := p
		t.Run(fmt.Sprintf("plant%d", i+1), func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "keyorix-server")
			buildServer(t, root, bin, applyPlant(t, root, p))
			st := runOnce(t, bin, filepath.Join(out, fmt.Sprintf("plant%d.jsonl", i+1)))
			writeCandidates(t, filepath.Join(out, fmt.Sprintf("plant%d-candidates.tsv", i+1)), st.Cands)
			found := false
			for _, c := range st.Cands {
				if p.detected(c) {
					found = true
					break
				}
			}
			t.Logf("plant %q: %d candidates, detected=%v", p.name, len(st.Cands), found)
			if !found {
				t.Fatalf("planted defect NOT detected: %s. The harness is broken; no clean result from this run can be believed.", p.name)
			}
		})
	}
}

// TestLiveReplay_Isolate replays only the candidates (and 5xx probes) listed in
// a previous results file, on LIVEREPLAY_REPEAT (default 3) fresh servers, and
// reports for each how often it reproduces. Output (request, response snippet,
// server log) goes to LIVEREPLAY_OUT and is private.
//
//	LIVEREPLAY_ISOLATE  results-runN.jsonl of an earlier run
func TestLiveReplay_Isolate(t *testing.T) {
	src := os.Getenv("LIVEREPLAY_ISOLATE")
	if src == "" {
		t.Skip("set LIVEREPLAY_ISOLATE")
	}
	raw, err := os.ReadFile(src) // #nosec G304,G703 -- operator-chosen input
	if err != nil {
		t.Fatal(err)
	}
	type rec struct {
		Variant, Actor, Op, Method, Target, Obj, Class, Detail, Req, Resp string
		Status                                                            int
	}
	var recs []rec
	for _, ln := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var m rec
		if json.Unmarshal([]byte(ln), &m) == nil && (strings.HasPrefix(m.Class, "CANDIDATE") || m.Class == ClassServerError) {
			recs = append(recs, m)
		}
	}
	reps := 3
	if n, err := strconv.Atoi(os.Getenv("LIVEREPLAY_REPEAT")); err == nil && n > 0 {
		reps = n
	}
	root := harness.RepoRoot(t)
	bin := filepath.Join(t.TempDir(), "keyorix-server")
	buildServer(t, root, bin, nil)
	out := outDir(t)
	hits := make([]int, len(recs))
	var report strings.Builder
	for rep := 1; rep <= reps; rep++ {
		srv, pw := bootThrowaway(t, bin)
		w := buildWorld(t, srv, pw)
		w.DriftFound = w.Calibrate(3)
		if pre := os.Getenv("LIVEREPLAY_ISOLATE_PRE"); pre != "" {
			// run the named operations' normal probes and controls first, to show
			// which earlier step a candidate depends on
			if pre == "machine-roles-control" {
				ap, _ := w.FirstID("A", "project")
				am, _ := w.FirstID("A", "machine")
				op, ok := w.matchOp("POST", "/api/v1/projects/"+ap+"/machine-identities/"+am+"/roles")
				if !ok {
					t.Fatal("machine roles operation not found")
				}
				p, ok := w.build(w.Actors["A"], op, "A", "control")
				if !ok {
					t.Fatal("cannot build the control")
				}
				st, b, _ := w.Do(w.Actors["A"], p.Method, p.Target, p.Body)
				fmt.Fprintf(&report, "PRE control as A: %s %s body=%s -> %d %.200s\n", p.Method, p.Target, p.Body, st, b)
			} else {
				w.Run(Options{Only: pre})
			}
			w.DriftFound = w.Calibrate(3)
		}
		// LIVEREPLAY_EXTRA: lines "ACTOR METHOD PATH [JSON body]" sent as-is, for
		// follow-up questions a triage raises (private output only).
		for _, ln := range strings.Split(os.Getenv("LIVEREPLAY_EXTRA"), ";") {
			f := strings.Fields(ln)
			if len(f) < 3 {
				continue
			}
			a := w.Actors[f[0]]
			if f[0] == "root" {
				a = w.Observer
			}
			var body []byte
			if len(f) > 3 {
				body = []byte(strings.Join(f[3:], " "))
			}
			st, b, _ := w.Do(a, f[1], f[2], body)
			fmt.Fprintf(&report, "EXTRA %s %s %s %s -> %d %.240s\n", f[0], f[1], f[2], body, st, b)
		}
		if rep == 1 {
			ap, _ := w.FirstID("A", "project")
			am, _ := w.FirstID("A", "machine")
			_, b, _ := w.Do(w.Observer, "GET", "/api/v1/projects/"+ap+"/machine-identities/"+am+"/roles", nil)
			fmt.Fprintf(&report, "MA machine-identity roles (root view, before probes): %.600s\n\n", b)
		}
		for i, m := range recs {
			path := m.Target
			if j := strings.IndexByte(path, '?'); j >= 0 {
				path = path[:j]
			}
			op, ok := w.matchOp(m.Method, path)
			if !ok {
				t.Fatalf("no operation for %s %s", m.Method, path)
			}
			r := w.exec(Probe{Variant: m.Variant, Actor: m.Actor, OpKey: m.Op, Method: m.Method, Target: m.Target, Body: []byte(m.Req), ObjTenant: m.Obj}, op)
			same := r.Class == m.Class
			if same {
				hits[i]++
			}
			fmt.Fprintf(&report, "rep%d %-22s same=%v status=%d actor=%s %s %s\n    req=%.200s\n    resp=%.300s\n    detail=%s\n", rep, r.Class, same, r.Status, m.Actor, m.Method, m.Target, m.Req, r.Resp, r.Detail)
		}
		if lb, err := os.ReadFile(srv.LogPath); err == nil { // #nosec G304 -- harness temp path
			_ = os.WriteFile(filepath.Join(out, fmt.Sprintf("isolate-rep%d.server.log", rep)), lb, 0o600) // #nosec G306 -- operator path
		}
	}
	fmt.Fprintf(&report, "\nreproduction in isolation (%d fresh servers):\n", reps)
	for i, m := range recs {
		fmt.Fprintf(&report, "  %d/%d  %s %s %s as %s\n", hits[i], reps, m.Class, m.Method, m.Target, m.Actor)
	}
	_ = os.WriteFile(filepath.Join(out, "isolate-report.txt"), []byte(report.String()), 0o600) // #nosec G306 -- operator path
	t.Log("isolation report written to " + filepath.Join(out, "isolate-report.txt"))
}
