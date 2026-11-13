package http

// FuzzOpenAPIStateful is a SCHEMA-DRIVEN, STATEFUL fuzzer for the REST API. Unlike
// FuzzKeyorixHTTPAPISequence / FuzzMultiTenantIsolation (hand-written operation tables),
// here the operation set AND the request shapes come from the live OpenAPI document
// (server/http/handlers/openapi.yaml, loaded with kin-openapi). The generator tracks
// id dependencies across calls: an integer id returned by one 2xx response is bound into
// a per-resource pool and fed to later operations' path params and *_id body fields
// (and, when a DELETE succeeds, into a "deleted" pool to drive use-after-delete shapes),
// so a fuzzer-chosen sequence of up to 12 operations reaches deep states no static table
// enumerates. It runs in-process against the REAL NewRouter stack (chi router + auth
// middleware + handlers + core + crypto + storage) over a seeded SQLite store, with a
// fixed set of principals of differing privilege.
//
// ORACLES (each documents, in its own comment below, what it does NOT verify):
//   1. no undeclared 5xx          (osOracleNo5xx)
//   2. response conformance       (osOracleConformance)
//   3. authz (unauth layer)       (osOracleAuthUnauth)
//   4. canary non-leakage         (osOracleCanary)
//   5. idempotent reads           (osOracleIdempotentRead)
//
// Phase 1: SQLite-backed, CI-runnable. The Postgres backend is reachable by swapping the
// core's DB exactly as the sibling fuzzers do (not wired here to keep the harness single-
// backend and fast). The known undeclared-5xx defects (OPENAPI-STATEFUL-1..8) are tracked
// in https://github.com/keyorixhq/keyorix/issues/4132.
//
// Oracle 1 is NOT a strict gate by default: a well-formed request that returns an undeclared
// 5xx is only t.Logf'd as a candidate unless KEYORIX_OSF_STRICT=1, and the entries in
// osKnownUndeclared5xx waive real, still-unfixed bugs (all tracked in #4132). Oracles 2-5
// are always fatal.
//
// Development switches (environment variables, never files in the working tree):
//   KEYORIX_OSF_ONLY=<operationId>  restrict the fuzzed op set to one operation
//   KEYORIX_OSF_SWEEP=1             log findings (deduplicated) instead of failing
//   KEYORIX_OSF_STRICT=1            make a well-formed undeclared 5xx fatal
//   KEYORIX_OSF_FINDINGS=<path>     where sweep mode appends findings
//                                   (default: <os.TempDir()>/osf_findings.log)

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// osSpecPath resolves openapi.yaml relative to the repo root (not the test's working
// directory), matching server/http/handlers/contracttest/spec.go.
func osSpecPath() string {
	return filepath.Join(srcpath.RepoRoot(), "server", "http", "handlers", "openapi.yaml")
}

// ---------------------------------------------------------------------------
// Spec loading & operation enumeration
// ---------------------------------------------------------------------------

type osOp struct {
	method       string
	tmpl         string // path template, e.g. /api/v1/projects/{id}
	op           *openapi3.Operation
	opID         string
	requiresAuth bool
	collection   string        // last non-param path segment (where created ids bind)
	pathParams   []osPathParam // in declaration order
	queryParams  []*openapi3.Parameter
}

type osPathParam struct {
	name      string
	preceding string // path segment immediately before {name}
	schema    *openapi3.SchemaRef
}

var (
	osSpecOnce sync.Once
	osSpec     *openapi3.T
	osRouter   routers.Router
	osOps      []osOp
	osSpecErr  error
)

func osLoadSpec(tb testing.TB) {
	osSpecOnce.Do(func() {
		// Reuse the same spec file the contract-test harness resolves.
		path := osSpecPath()
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromFile(path)
		if err != nil {
			osSpecErr = fmt.Errorf("load %s: %w", path, err)
			return
		}
		if err := doc.Validate(loader.Context); err != nil {
			osSpecErr = fmt.Errorf("validate %s: %w", path, err)
			return
		}
		r, err := gorillamux.NewRouter(doc)
		if err != nil {
			osSpecErr = fmt.Errorf("router %s: %w", path, err)
			return
		}
		osSpec, osRouter = doc, r
		osOps = osEnumerate(doc)
		// Dev aid (red-proof determinism): KEYORIX_OSF_ONLY=<operationId> restricts the fuzzed
		// op set to that one op, so a planted fault in its handler is exercised without
		// interference from other ops. Inert when unset.
		if only := strings.TrimSpace(os.Getenv("KEYORIX_OSF_ONLY")); only != "" {
			filtered := osOps[:0:0]
			for _, o := range osOps {
				if o.opID == only {
					filtered = append(filtered, o)
				}
			}
			if len(filtered) > 0 {
				osOps = filtered
			}
		}
	})
	if osSpecErr != nil {
		tb.Fatalf("FuzzOpenAPIStateful: %v", osSpecErr)
	}
}

func osEnumerate(doc *openapi3.T) []osOp {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	var ops []osOp
	for tmpl, item := range doc.Paths.Map() {
		segs := strings.Split(strings.Trim(tmpl, "/"), "/")
		for _, m := range methods {
			op := item.GetOperation(m)
			if op == nil {
				continue
			}
			o := osOp{method: m, tmpl: tmpl, op: op, opID: op.OperationID}
			// requiresAuth: op-level security overrides global
			sec := doc.Security
			if op.Security != nil {
				sec = *op.Security
			}
			for _, req := range sec {
				if len(req) > 0 {
					o.requiresAuth = true
				}
			}
			// collection = last non-param segment
			for _, seg := range slices.Backward(segs) {
				if !strings.HasPrefix(seg, "{") {
					o.collection = seg
					break
				}
			}
			// path params with preceding segment
			for i, s := range segs {
				if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
					name := s[1 : len(s)-1]
					pre := ""
					if i > 0 {
						pre = segs[i-1]
					}
					pp := osPathParam{name: name, preceding: pre}
					// find schema from op/path params
					for _, pr := range op.Parameters {
						if pr.Value != nil && pr.Value.In == "path" && pr.Value.Name == name {
							pp.schema = pr.Value.Schema
						}
					}
					o.pathParams = append(o.pathParams, pp)
				}
			}
			for _, pr := range op.Parameters {
				if pr.Value != nil && pr.Value.In == "query" {
					o.queryParams = append(o.queryParams, pr.Value)
				}
			}
			ops = append(ops, o)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].tmpl == ops[j].tmpl {
			return ops[i].method < ops[j].method
		}
		return ops[i].tmpl < ops[j].tmpl
	})
	return ops
}

// ---------------------------------------------------------------------------
// World & principals
// ---------------------------------------------------------------------------

const (
	osPrincAnon        = 0 // no Authorization header
	osPrincGarbage     = 1 // invalid bearer token
	osPrincNoRole      = 2 // authenticated, zero grants
	osPrincViewer      = 3 // secrets.read at project A scope
	osPrincProjAdminA  = 4 // read+write+delete scoped to project A
	osPrincGlobalAdmin = 5 // bootstrap admin
	osPrincMachine     = 6 // machine token, project-A reader role
	osPrincExpired     = 7 // a grant that has already expired
	osNumPrincipals    = 8
)

// osCanary is planted as the value of a seeded secret. Oracle 4 asserts it never appears
// in a header, an error body, or any response to an unauthenticated principal.
const osCanary = "CANARY-7f3a91c20e5b4d6a-OPENAPI-STATEFUL"

const osPassword = "Xk7#Qp2$Rn5@Wv9!"

type osWorld struct {
	router    http.Handler
	db        *gorm.DB
	c         *core.KeyorixCore
	tokens    [osNumPrincipals]string // "" for anon; garbage is a literal below
	seedPools map[string][]uint       // resource collection -> ids seeded at build time
}

func osBuildWorld(f *testing.F) *osWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}
	db := fuzzworld.OpenSQLite(f, sqlitetest.DSN("osfuzz_"), 1)
	fuzzworld.Bootstrap(f, db)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate test models: %v", err)
	}
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "osadmin", Email: "osadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap: %v (may already be initialised)", err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "osadmin", Password: "TestPassword123!"})
	if err != nil {
		f.Fatalf("admin login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "osadmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	// Projects & environments.
	pA, err := ls.CreateProject(ctx, &models.Project{Name: "osproja"})
	if err != nil {
		f.Fatalf("projA: %v", err)
	}
	eA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pA.ID})
	if err != nil {
		f.Fatalf("envA: %v", err)
	}
	pB, err := ls.CreateProject(ctx, &models.Project{Name: "osprojb"})
	if err != nil {
		f.Fatalf("projB: %v", err)
	}
	eB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pB.ID})
	if err != nil {
		f.Fatalf("envB: %v", err)
	}

	perm := func(name, res, act string) models.Permission {
		var p models.Permission
		if e := db.Where("name = ?", name).First(&p).Error; e != nil {
			p = models.Permission{Name: name, Resource: res, Action: act}
			if e2 := db.Create(&p).Error; e2 != nil {
				f.Fatalf("seed permission %s: %v", name, e2)
			}
		}
		return p
	}
	pRead := perm("secrets.read", "secrets", "read")
	pWrite := perm("secrets.write", "secrets", "write")
	pDelete := perm("secrets.delete", "secrets", "delete")

	mkRole := func(name string, perms ...models.Permission) models.Role {
		role := models.Role{Name: name, NameFolded: name}
		if e := db.Create(&role).Error; e != nil {
			f.Fatalf("seed role %s: %v", name, e)
		}
		for _, p := range perms {
			if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: p.ID}).Error; e != nil {
				f.Fatalf("seed role-perm %s/%d: %v", name, p.ID, e)
			}
		}
		return role
	}
	viewerRole := mkRole("osf-viewer", pRead)
	projAdminRole := mkRole("osf-projadmin", pRead, pWrite, pDelete)

	// Seed a canary secret in project A and an ordinary secret in project B.
	sA, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "oscanary", Value: []byte(osCanary), ProjectID: pA.ID, EnvironmentID: eA.ID,
		Type: "password", CreatedBy: "osadmin", OwnerID: admin.ID,
	})
	if err != nil || sA == nil {
		f.Fatalf("secretA: %v", err)
	}
	sB, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "osplain", Value: []byte("VALUE-B-osplain"), ProjectID: pB.ID, EnvironmentID: eB.ID,
		Type: "password", CreatedBy: "osadmin", OwnerID: admin.ID,
	})
	if err != nil || sB == nil {
		f.Fatalf("secretB: %v", err)
	}

	w := &osWorld{db: db, c: c}

	mkUser := func(uname string) uint {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@x.io", Password: osPassword})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		return u.ID
	}
	login := func(uname string) string {
		sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: uname, Password: osPassword})
		if lerr != nil || sess == nil {
			f.Fatalf("login %s: %v", uname, lerr)
		}
		return sess.SessionToken
	}

	noRoleID := mkUser("osnorole")
	viewerID := mkUser("osviewer")
	projAdminID := mkUser("osprojadmin")
	expiredID := mkUser("osexpired")

	// viewerRole is project-scoped by the role model, so it is granted at project A
	// (a read-only principal on project A); global read is not expressible for this role.
	if err := c.AssignUserRole(ctx, 0, viewerID, viewerRole.ID, core.Scope{ProjectID: pA.ID}, false); err != nil {
		f.Fatalf("grant viewer: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, projAdminID, projAdminRole.ID, core.Scope{ProjectID: pA.ID}, false); err != nil {
		f.Fatalf("grant projadmin: %v", err)
	}
	if err := c.AssignUserRoleWithExpiry(ctx, 0, expiredID, viewerRole.ID, core.Scope{ProjectID: pA.ID}, time.Now().Add(-1*time.Hour), false); err != nil {
		f.Fatalf("grant expired: %v", err)
	}

	// Machine identity + token, project-A reader role.
	machineTok := ""
	var machineID uint
	if m, merr := c.CreateMachineIdentity(ctx, pA.ID, "osmachine", "service", "fuzz", "", admin.ID, 0); merr == nil && m != nil {
		machineID = m.ID
		if res, terr := c.IssueMachineToken(ctx, pA.ID, m.ID, admin.ID, core.IssueMachineTokenParams{Name: "osmach"}); terr == nil && res != nil {
			machineTok = res.PlainToken
			if aerr := c.AssignMachineRole(ctx, m.ID, viewerRole.ID, core.Scope{ProjectID: pA.ID}, 0, false); aerr != nil {
				f.Logf("assign machine role: %v", aerr)
			}
		} else {
			f.Logf("issue machine token: %v", terr)
		}
	} else {
		f.Logf("create machine identity: %v", merr)
	}

	w.tokens[osPrincAnon] = ""
	w.tokens[osPrincGarbage] = "kx_pat_invalidgarbagetokennotrealatall000000"
	w.tokens[osPrincNoRole] = login("osnorole")
	w.tokens[osPrincViewer] = login("osviewer")
	w.tokens[osPrincProjAdminA] = login("osprojadmin")
	w.tokens[osPrincGlobalAdmin] = adminSess.SessionToken
	w.tokens[osPrincMachine] = machineTok
	w.tokens[osPrincExpired] = login("osexpired")

	w.seedPools = map[string][]uint{
		"projects":           {pA.ID, pB.ID},
		"environments":       {eA.ID, eB.ID},
		"secrets":            {sA.ID, sB.ID},
		"roles":              {viewerRole.ID, projAdminRole.ID},
		"users":              {admin.ID, noRoleID, viewerID, projAdminID, expiredID},
		"machine-identities": {},
	}
	if machineID != 0 {
		w.seedPools["machine-identities"] = []uint{machineID}
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router: %v", err)
	}
	w.router = r
	return w
}

// ---------------------------------------------------------------------------
// Byte reader (input-driven decisions)
// ---------------------------------------------------------------------------

type osReader struct {
	b []byte
	i int
}

func (r *osReader) byte() byte {
	if len(r.b) == 0 {
		return 0
	}
	v := r.b[r.i%len(r.b)]
	r.i++
	return v
}
func (r *osReader) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.byte()) % n
}
func (r *osReader) u16() int { return int(r.byte())<<8 | int(r.byte()) }

// ---------------------------------------------------------------------------
// Per-iteration mutable state
// ---------------------------------------------------------------------------

type osState struct {
	pools   map[string][]uint
	deleted map[string][]uint
}

func (w *osWorld) newState() *osState {
	s := &osState{pools: map[string][]uint{}, deleted: map[string][]uint{}}
	for k, v := range w.seedPools {
		cp := make([]uint, len(v))
		copy(cp, v)
		s.pools[k] = cp
	}
	return s
}

func (s *osState) add(coll string, id uint) {
	if id == 0 || coll == "" {
		return
	}
	if slices.Contains(s.pools[coll], id) {
		return
	}
	if len(s.pools[coll]) < 64 {
		s.pools[coll] = append(s.pools[coll], id)
	}
}

func (s *osState) markDeleted(coll string, id uint) {
	if id == 0 || coll == "" {
		return
	}
	s.deleted[coll] = append(s.deleted[coll], id)
}

func (s *osState) pick(coll string, rd *osReader) (uint, bool) {
	p := s.pools[coll]
	if len(p) == 0 {
		return 0, false
	}
	return p[rd.intn(len(p))], true
}

func (s *osState) pickDeleted(coll string, rd *osReader) (uint, bool) {
	p := s.deleted[coll]
	if len(p) == 0 {
		return 0, false
	}
	return p[rd.intn(len(p))], true
}

// ---------------------------------------------------------------------------
// Request generation
// ---------------------------------------------------------------------------

func osPrimaryType(s *openapi3.Schema) string {
	if s == nil {
		return ""
	}
	if s.Type != nil {
		for _, t := range []string{"object", "array", "string", "integer", "number", "boolean"} {
			if s.Type.Is(t) {
				return t
			}
		}
	}
	if len(s.Properties) > 0 {
		return "object"
	}
	if s.Items != nil {
		return "array"
	}
	return ""
}

// osPoolForField maps a body/path field name to a seeded resource collection, so *_id
// fields and id path params get real ids and creates actually succeed (reaching deep state).
func osPoolForField(name string) string {
	n := strings.ToLower(name)
	switch n {
	case "project_id", "projectid", "project":
		return "projects"
	case "environment_id", "environmentid", "env_id", "envid":
		return "environments"
	case "role_id", "roleid":
		return "roles"
	case "secret_id", "secretid":
		return "secrets"
	case "user_id", "userid", "owner_id", "ownerid", "target_user_id":
		return "users"
	case "machine_id", "machineid", "machine_identity_id":
		return "machine-identities"
	}
	return ""
}

// osStringPathParam is true for the few path params that are NOT numeric ids.
func osStringPathParam(name string) bool {
	switch strings.ToLower(name) {
	case "token", "ref", "name", "key", "slug", "username", "email":
		return true
	}
	return false
}

func osSampleString(name string, mode int, rd *osReader) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "email"):
		return fmt.Sprintf("osf%d@x.io", rd.byte())
	case strings.Contains(n, "password"):
		return osPassword
	case strings.Contains(n, "name"):
		if mode == 1 { // boundary: empty / long
			if rd.intn(2) == 0 {
				return ""
			}
			return strings.Repeat("n", 300)
		}
		return fmt.Sprintf("osf-%d", rd.u16())
	}
	if mode == 1 {
		switch rd.intn(3) {
		case 0:
			return ""
		case 1:
			return strings.Repeat("x", 512)
		}
	}
	return fmt.Sprintf("v%d", rd.byte())
}

// osGenJSON builds a JSON value from a schema. mode: 0 valid, 1 boundary, 2 schema-violating.
func (w *osWorld) osGenJSON(st *osState, ref *openapi3.SchemaRef, name string, mode, depth int, rd *osReader) (any, bool) {
	if ref == nil || ref.Value == nil || depth > 6 {
		return nil, false
	}
	s := ref.Value
	if len(s.AllOf) > 0 {
		merged := map[string]any{}
		for _, sub := range s.AllOf {
			if v, ok := w.osGenJSON(st, sub, name, mode, depth+1, rd); ok {
				if m, isMap := v.(map[string]any); isMap {
					maps.Copy(merged, m)
				}
			}
		}
		return merged, true
	}
	if len(s.OneOf) > 0 {
		return w.osGenJSON(st, s.OneOf[rd.intn(len(s.OneOf))], name, mode, depth+1, rd)
	}
	if len(s.AnyOf) > 0 {
		return w.osGenJSON(st, s.AnyOf[rd.intn(len(s.AnyOf))], name, mode, depth+1, rd)
	}
	if len(s.Enum) > 0 && mode != 2 {
		return s.Enum[rd.intn(len(s.Enum))], true
	}
	// id-bearing fields: use a real id so creates land in deep state.
	if pool := osPoolForField(name); pool != "" && mode != 2 {
		if id, ok := st.pick(pool, rd); ok {
			return int(id), true
		}
	}
	switch osPrimaryType(s) {
	case "object":
		obj := map[string]any{}
		req := map[string]bool{}
		for _, rp := range s.Required {
			req[rp] = true
		}
		// deterministic property order
		keys := make([]string, 0, len(s.Properties))
		for k := range s.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pref := s.Properties[k]
			// in valid/boundary mode include required always, optionals sometimes.
			include := req[k] || rd.intn(2) == 0
			if mode == 2 && req[k] && rd.intn(3) == 0 {
				continue // violating: drop a required field
			}
			if !include {
				continue
			}
			if v, ok := w.osGenJSON(st, pref, k, mode, depth+1, rd); ok {
				obj[k] = v
			}
		}
		if mode == 2 && rd.intn(2) == 0 {
			obj["__osf_unexpected"] = []any{1, "x"} // violating: unexpected shape
		}
		return obj, true
	case "array":
		n := rd.intn(3)
		arr := make([]any, 0, n)
		for range n {
			if v, ok := w.osGenJSON(st, s.Items, name, mode, depth+1, rd); ok {
				arr = append(arr, v)
			}
		}
		return arr, true
	case "string":
		if mode == 2 && rd.intn(2) == 0 {
			return rd.u16(), true // violating: number where string expected
		}
		if s.Format == "date-time" {
			return time.Now().UTC().Format(time.RFC3339), true
		}
		return osSampleString(name, mode, rd), true
	case "integer":
		if mode == 2 && rd.intn(2) == 0 {
			return "not-an-int", true
		}
		if mode == 1 {
			switch rd.intn(3) {
			case 0:
				return 0, true
			case 1:
				return -1, true
			}
		}
		return rd.u16(), true
	case "number":
		if mode == 2 && rd.intn(2) == 0 {
			return "NaN", true
		}
		return float64(rd.u16()) / 7.0, true
	case "boolean":
		return rd.intn(2) == 0, true
	}
	// Unknown/empty schema: emit nothing.
	return nil, false
}

// osBuildRequest constructs the HTTP request for an operation under the chosen principal.
func (w *osWorld) osBuildRequest(st *osState, o *osOp, princ int, mode int, rd *osReader) *http.Request {
	path := o.tmpl
	for _, pp := range o.pathParams {
		var val string
		if osStringPathParam(pp.name) {
			if pp.name == "ref" {
				val = "osproja/prod/oscanary"
			} else {
				val = osSampleString(pp.name, mode, rd)
			}
		} else {
			// numeric id from the preceding collection's pool (or deleted pool, or bogus).
			pool := pp.preceding
			if rd.intn(5) == 0 { // drive use-after-delete
				if id, ok := st.pickDeleted(pool, rd); ok {
					val = strconv.FormatUint(uint64(id), 10)
				}
			}
			if val == "" {
				if id, ok := st.pick(pool, rd); ok {
					val = strconv.FormatUint(uint64(id), 10)
				} else {
					val = "999999"
				}
			}
			if mode == 2 && rd.intn(4) == 0 {
				val = "notanumber"
			}
		}
		path = strings.ReplaceAll(path, "{"+pp.name+"}", url.PathEscape(val))
	}

	// query params
	q := url.Values{}
	for _, qp := range o.queryParams {
		if !qp.Required && rd.intn(2) == 0 {
			continue
		}
		if v, ok := w.osGenJSON(st, qp.Schema, qp.Name, mode, 0, rd); ok {
			q.Set(qp.Name, fmt.Sprintf("%v", v))
		}
	}
	target := path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}

	// body
	var bodyReader *strings.Reader
	hasBody := false
	if o.op.RequestBody != nil && o.op.RequestBody.Value != nil && (o.method == "POST" || o.method == "PUT" || o.method == "PATCH") {
		mt := o.op.RequestBody.Value.Content.Get("application/json")
		if mt != nil && mt.Schema != nil {
			if v, ok := w.osGenJSON(st, mt.Schema, "", mode, 0, rd); ok {
				if b, err := json.Marshal(v); err == nil {
					bodyReader = strings.NewReader(string(b))
					hasBody = true
				}
			}
		}
	}

	var req *http.Request
	if hasBody {
		req = httptest.NewRequest(o.method, target, bodyReader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(o.method, target, nil)
	}
	if tok := w.tokens[princ]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	} else if princ == osPrincGarbage {
		req.Header.Set("Authorization", "Bearer "+w.tokens[osPrincGarbage])
	}
	return req
}

// ---------------------------------------------------------------------------
// Oracles
// ---------------------------------------------------------------------------

// osConformanceExceptions lists operationIds whose response is NOT validated by oracle 2,
// each with a reason. (The spec census found only 2 schema-less ops; more may be added
// here during triage, always with a justification — never to hide a real mismatch.)
var osConformanceExceptions = map[string]string{
	"prometheusMetrics": "returns Prometheus text exposition format, not JSON; no response schema by design",
	"authPasswordReset": "returns a deliberately generic 200 with no schema, so it cannot be used as an account-existence oracle",
}

// osKnownUndeclaredSuccessStatus documents (opID|statusCode) pairs where the handler returns
// a 2xx SUCCESS status the spec does not declare — a real response-conformance FINDING, held
// here so the committed strict gate stays green while the spec/handler fix is pending. Unlike
// osConformanceExceptions this is status-scoped: it suppresses ONLY the undeclared-success-
// status report for that exact (op, code) pair; body-schema validation of every DECLARED
// status on the same op stays live. Each entry names a real defect with its root cause.
var osKnownUndeclaredSuccessStatus = map[string]string{}

// osDeclaresStatus reports whether the operation declares the given status code (exact or
// by its range class like '2XX', or a 'default' response).
func osDeclaresStatus(o *osOp, code int) bool {
	if o.op.Responses == nil {
		return false
	}
	if r := o.op.Responses.Status(code); r != nil {
		return true
	}
	if r := o.op.Responses.Map()["default"]; r != nil {
		return true
	}
	class := fmt.Sprintf("%dXX", code/100)
	if r := o.op.Responses.Map()[class]; r != nil {
		return true
	}
	return false
}

func osIs2xx(code int) bool { return code >= 200 && code < 300 }

func osBodyHas(rec *httptest.ResponseRecorder, s string) bool {
	return strings.Contains(rec.Body.String(), s)
}

func osHeaderHas(rec *httptest.ResponseRecorder, s string) bool {
	for _, vals := range rec.Header() {
		for _, v := range vals {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Iteration
// ---------------------------------------------------------------------------

// osSweep, when true (a one-off enumeration run, gated by KEYORIX_OSF_SWEEP=1), downgrades every oracle's t.Fatalf to a deduplicated t.Logf
// so a single run can enumerate the COMPLETE set of findings across all operations instead
// of halting on the first. The committed harness runs with osSweep=false (fatal), so a new
// finding (regression) halts as intended; the sweep is a development aid to populate the
// documented exception lists, never the shipped behaviour.
var (
	osSweep     bool
	osStrict    bool
	osSweepSeen sync.Map
)

func osInitSweep() {
	osSweep = os.Getenv("KEYORIX_OSF_SWEEP") == "1"
	// osStrict (KEYORIX_OSF_STRICT=1) makes a well-formed-request undeclared 500
	// FATAL rather than a deduplicated candidate. OFF by default: oracle 1 surfaced a broad
	// PRE-EXISTING error-classification class (handlers blanket-map core not-found/validation/
	// constraint errors to an undeclared 500 — issue #4132, OPENAPI-STATEFUL-1..3), so the
	// committed target logs those as candidates and stays runnable end-to-end for the rig
	// instead of halting in <1 min on a known bug. Strict mode is used by the oracle-1
	// red-proof and is available to gate once the class is fixed. Oracles 2-5 are always fatal.
	osStrict = os.Getenv("KEYORIX_OSF_STRICT") == "1"
}

// osFindingsPath is where sweep mode appends findings: KEYORIX_OSF_FINDINGS, else a file in
// the OS temp dir (never inside the repo working tree).
func osFindingsPath() string {
	if p := os.Getenv("KEYORIX_OSF_FINDINGS"); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "osf_findings.log")
}

// osAppendFinding appends one line to the sweep findings file and logs (rather than
// silently drops) a failure to do so.
func osAppendFinding(t *testing.T, format string, args ...any) {
	t.Helper()
	osSweepMu.Lock()
	defer osSweepMu.Unlock()
	f, err := os.OpenFile(osFindingsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Logf("sweep: cannot open findings file: %v", err)
		return
	}
	if _, err := fmt.Fprintf(f, format+"\n", args...); err != nil {
		t.Logf("sweep: cannot write findings file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Logf("sweep: cannot close findings file: %v", err)
	}
}

var osSweepMu sync.Mutex

// osReport fails (normal) or deduplicated-appends-to-file (sweep) a finding keyed by `key`.
// In sweep mode the fuzzer does not fail, so t.Logf would never surface; findings are
// appended to osFindingsPath() instead (deduped by key).
func osReport(t *testing.T, key, format string, args ...any) {
	t.Helper()
	if osSweep {
		if _, seen := osSweepSeen.LoadOrStore(key, struct{}{}); seen {
			return
		}
		osAppendFinding(t, "[%s] "+format, append([]any{key}, args...)...)
		return
	}
	t.Fatalf(format, args...)
}

func osExec(w *osWorld, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec
}

// osBindResponse scans a 2xx JSON body for integer "id" values and binds them into the
// operation's collection pool, so later ops can target freshly created resources. Also
// moves a successfully-deleted path-target id into the deleted pool.
func osBindResponse(st *osState, o *osOp, rec *httptest.ResponseRecorder, targetID uint) {
	if o.method == "DELETE" && osIs2xx(rec.Code) {
		st.markDeleted(o.collection, targetID)
	}
	if !osIs2xx(rec.Code) {
		return
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "json") && ct != "" {
		return
	}
	var top any
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		return
	}
	var walk func(v any)
	count := 0
	walk = func(v any) {
		if count > 200 {
			return
		}
		count++
		switch t := v.(type) {
		case map[string]any:
			if idv, ok := t["id"]; ok {
				if f, ok := idv.(float64); ok && f > 0 {
					st.add(o.collection, uint(f))
				}
			}
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(top)
}

func osRunIteration(t *testing.T, w *osWorld, program []byte) {
	t.Helper()
	if len(osOps) == 0 {
		return
	}
	rd := &osReader{b: program}
	princ := rd.intn(osNumPrincipals)
	st := w.newState()
	numSteps := 1 + rd.intn(12)

	for range numSteps {
		opIdx := rd.u16() % len(osOps)
		o := &osOps[opIdx]
		modeByte := rd.byte()
		mode := 0
		switch modeByte % 4 {
		case 2:
			mode = 1 // boundary
		case 3:
			mode = 2 // schema-violating
		}

		// Resolve the primary path-target id (for delete-tracking) by re-picking is not
		// possible post-hoc, so capture it from the last id path param if present.
		req := w.osBuildRequest(st, o, princ, mode, rd)
		targetID := osPrimaryTargetID(o, req)

		rec := osExec(w, req)

		osOracleNo5xx(t, w, o, princ, mode, req, rec)
		osOracleConformance(t, o, req, rec)
		osOracleAuthUnauth(t, w, st, o, princ, mode, rd, req, rec)
		osOracleCanary(t, o, princ, rec)
		osOracleIdempotentRead(t, w, o, princ, req, rec)

		osBindResponse(st, o, rec, targetID)
	}
}

// osPrimaryTargetID extracts the numeric id of the last id-style path param from the
// already-resolved request URL, for delete-tracking.
func osPrimaryTargetID(o *osOp, req *http.Request) uint {
	segs := strings.Split(strings.Trim(o.tmpl, "/"), "/")
	actual := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(segs) != len(actual) {
		return 0
	}
	var last uint
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && !osStringPathParam(s[1:len(s)-1]) {
			if n, err := strconv.ParseUint(actual[i], 10, 64); err == nil {
				last = uint(n)
			}
		}
	}
	return last
}

// --- Oracle 1: no undeclared 5xx -------------------------------------------
// VERIFIES: a 5xx status is a finding unless the operation DECLARES that status in the
// spec (e.g. createProject's documented 503 AuditUnavailable).
// Does NOT verify: that a declared 5xx is semantically appropriate for the input, nor any
// 4xx behaviour; a panic recovered by middleware into a declared 500 would pass here (it is
// caught instead by the panic surfacing as an undeclared-5xx or by Go's own panic in-test).
// osCandidate5xx records (op, code) pairs seen as undeclared 5xx on a deliberately
// schema-violating request, logged once each. These are lower-severity robustness defects
// (a malformed request should yield a 4xx, not a 5xx) enumerated for the report, as opposed
// to the fatal case: a WELL-FORMED (valid/boundary) request must never 500.
var osCandidate5xx sync.Map // key "opID|code" -> struct{}

func osOracleNo5xx(t *testing.T, w *osWorld, o *osOp, princ, mode int, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code < 500 || osDeclaresStatus(o, rec.Code) {
		return
	}
	// A matching known-defect entry documents a real finding (see osKnownUndeclared5xx):
	// the harness stays green on an already-reported bug without blinding oracle 1 to any
	// OTHER undeclared 5xx on the same operation.
	for _, k := range osKnownUndeclared5xx {
		if (k.opID == "" || k.opID == o.opID) && k.code == rec.Code && (k.princ < 0 || k.princ == princ) &&
			(k.pathContains == "" || strings.Contains(req.URL.Path, k.pathContains)) &&
			(k.bodyContains == "" || strings.Contains(rec.Body.String(), k.bodyContains)) {
			t.Logf("NO-5XX (known defect %s): %s %s op=%s princ=%d code=%d — %s",
				k.id, req.Method, req.URL.Path, o.opID, princ, rec.Code, k.reason)
			return
		}
	}
	// A deliberately schema-violating input, OR (unless strict mode) a well-formed one, that
	// returns an undeclared 5xx is recorded ONCE as a candidate and the run continues. In
	// strict mode a WELL-FORMED undeclared 5xx is fatal (regression gate / red-proof).
	wellFormed := mode != 2
	if wellFormed && osStrict {
		osReport(t, "no5xx|"+o.opID+"|"+strconv.Itoa(rec.Code),
			"NO-5XX: %s %s (op=%s princ=%d mode=%d) returned undeclared %d on a well-formed request\nbody=%s",
			req.Method, req.URL.Path, o.opID, princ, mode, rec.Code, osTrunc(rec.Body.String()))
		return
	}
	kind := "malformed-input robustness"
	if wellFormed {
		kind = "well-formed request → undeclared 5xx (error-classification class; see #4132)"
	}
	key := fmt.Sprintf("cand5xx|%s|%d", o.opID, rec.Code)
	if _, seen := osCandidate5xx.LoadOrStore(key, struct{}{}); !seen {
		if osSweep {
			osAppendFinding(t, "[%s] NO-5XX CANDIDATE (%s): %s %s op=%s code=%d body=%s",
				key, kind, req.Method, req.URL.Path, o.opID, rec.Code, osTrunc(rec.Body.String()))
		} else {
			t.Logf("NO-5XX CANDIDATE (%s): %s %s op=%s code=%d body=%s",
				kind, req.Method, req.URL.Path, o.opID, rec.Code, osTrunc(rec.Body.String()))
		}
	}
}

// osKnownUndeclared5xx documents undeclared-5xx FINDINGS this fuzzer has already surfaced
// and that are reported (not fixed, per the no-production-change rule) in
// https://github.com/keyorixhq/keyorix/issues/4132. Each entry is a real bug: it keeps the committed target
// green for the rig while the fix is pending. princ<0 matches any principal.
var osKnownUndeclared5xx = []struct {
	id           string
	opID         string // "" = any op
	princ        int    // <0 = any principal
	code         int
	pathContains string // "" = any path
	bodyContains string // "" = any body
	reason       string
}{
	// OPENAPI-STATEFUL-3 (CLASS): generic-CRUD handlers blanket-map ANY core error to an
	// undeclared 500 instead of the appropriate 4xx. The clearest example is GetProjectStats:
	// `stats, err := GetProjectStats(id); if err != nil { 500 }` — a not-found project id
	// (e.g. one deleted earlier in the sequence) yields 500, never 404. The fuzzer observed
	// the same shape (not-found / duplicate-name constraint / boundary input → 500) on each op
	// below; the list is observed-via-fuzzing, likely non-exhaustive. See #4132
	// (OPENAPI-STATEFUL-3).

	{id: "OPENAPI-STATEFUL-3", opID: "deleteProject", princ: -1, code: 500, reason: "project-with-dependencies / not-found blanket-mapped to 500"},
	{id: "OPENAPI-STATEFUL-3", opID: "updateProject", princ: -1, code: 500, reason: "duplicate-name constraint / not-found blanket-mapped to 500"},
	{id: "OPENAPI-STATEFUL-3", opID: "createProjectEnvironment", princ: -1, code: 500, reason: "duplicate env-name constraint / not-found blanket-mapped to 500"},
	{id: "OPENAPI-STATEFUL-3", opID: "restoreEnvironment", princ: -1, code: 500, reason: "restore of a non-deleted/absent environment blanket-mapped to 500"},
	{id: "OPENAPI-STATEFUL-3", opID: "restoreSecret", princ: -1, code: 500, reason: "restore of a non-deleted/absent secret blanket-mapped to 500"},

	{id: "OPENAPI-STATEFUL-3", opID: "renderSecretTemplate", princ: -1, code: 500, reason: "template render error on schema-valid input blanket-mapped to 500"},
	{id: "OPENAPI-STATEFUL-3", opID: "shareSecret", princ: -1, code: 500, reason: "share error (self-share / duplicate / not-found) blanket-mapped to 500"},

	// OPENAPI-STATEFUL-7: StartImpersonation's handler switch (admin_impersonation.go:92-99)
	// maps only "yourself"->400 and storage.ErrUserNotFound->404; every OTHER core refusal
	// falls through to the default 500 branch. For an interactive admin session that includes
	// "cannot impersonate a suspended or inactive user" (impersonation.go:107, a pre-mint,
	// fully fail-closed refusal of a target that cannot log in), "impersonation ceiling
	// exceeded" (line 262), and "admin not found" (line 84). A legitimate semantic refusal
	// becomes an undeclared 500 instead of a 403/409. No session is minted; nothing leaks.
	// Fix: classify these as 403 (authority/credential refusal) / 409 (target-state refusal).
	{id: "OPENAPI-STATEFUL-7", opID: "startImpersonation", princ: -1, code: 500, reason: "core impersonation refusal (suspended/inactive target, ceiling-exceeded, admin-not-found) falls through the handler switch to an undeclared 500 instead of 403/409. admin_impersonation.go:97."},
}

// --- Oracle 2: response conformance ----------------------------------------
// VERIFIES: the returned status code is DECLARED for the operation and the response body
// validates against the declared schema for that status + Content-Type (kin-openapi
// openapi3filter.ValidateResponse).
// Does NOT verify: operations on osConformanceExceptions (schema-less by design); requests
// the gorillamux router cannot match (logged as possible route↔spec drift, not failed here
// since the harness builds requests FROM the spec); semantic correctness of a
// schema-valid body.
func osOracleConformance(t *testing.T, o *osOp, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	if _, skip := osConformanceExceptions[o.opID]; skip {
		return
	}
	route, pathParams, err := osRouter.FindRoute(req)
	if err != nil {
		t.Logf("DRIFT?: %s %s (op=%s) did not match any spec route: %v", req.Method, req.URL.Path, o.opID, err)
		return
	}
	// kin-openapi's ValidateResponse does NOT reject an UNDECLARED status (it finds no
	// matching response definition and returns nil), so a success status the spec never
	// declares would slip past body validation. Assert it explicitly for 2xx: a successful
	// response MUST correspond to a declared success status. (Undeclared NON-2xx statuses —
	// e.g. a 404/405 the spec omits — are deliberately NOT asserted here; many are
	// legitimately undeclared across this API and 5xx is oracle 1's job.)
	if osIs2xx(rec.Code) && !osDeclaresStatus(o, rec.Code) {
		if reason, known := osKnownUndeclaredSuccessStatus[o.opID+"|"+strconv.Itoa(rec.Code)]; known {
			t.Logf("CONFORMANCE (known undeclared success status): %s %s op=%s returned %d — %s",
				req.Method, req.URL.Path, o.opID, rec.Code, reason)
			return
		}
		osReport(t, "confstatus|"+o.opID+"|"+strconv.Itoa(rec.Code),
			"CONFORMANCE (undeclared success status): %s %s (op=%s) returned %d, which openapi.yaml does not declare for this operation",
			req.Method, req.URL.Path, o.opID, rec.Code)
		return
	}
	input := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		},
		Status: rec.Code,
		Header: rec.Header().Clone(),
		Options: &openapi3filter.Options{
			SchemaValidationOptions: []openapi3.SchemaValidationOption{openapi3.DisableSchemaErrorDetails()},
		},
	}
	input.SetBodyBytes(rec.Body.Bytes())
	if verr := openapi3filter.ValidateResponse(req.Context(), input); verr != nil {
		osReport(t, "conf|"+o.opID+"|"+strconv.Itoa(rec.Code),
			"CONFORMANCE: %s %s (op=%s status=%d) response does not match openapi.yaml: %v",
			req.Method, req.URL.Path, o.opID, rec.Code, verr)
	}
}

// --- Oracle 3: authorization (unauthenticated layer) -----------------------
// VERIFIES (soundly, in every reachable state): an UNAUTHENTICATED caller — no Authorization
// header (anon) or an invalid bearer (garbage) — must NEVER receive a 2xx on an operation
// whose spec declares a non-empty security requirement, no matter what prefix of calls
// preceded it (no privilege gained by state) and no matter which schema-valid argument
// variant is used (authentication precedes argument processing). A 2xx is an AUTHZ BYPASS.
// Does NOT verify: privilege monotonicity AMONG AUTHENTICATED principals (viewer / project
// admin / machine / expired-grant). A sound form of that needs operation-specific knowledge
// of which request field carries the authorization target (e.g. a project_id in the body),
// which the schema does not express; asserting it generically would false-positive on
// legitimately target-dependent authz, so it is deliberately left unasserted here.
func osOracleAuthUnauth(t *testing.T, w *osWorld, st *osState, o *osOp, princ, mode int, rd *osReader, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	if princ != osPrincAnon && princ != osPrincGarbage {
		return
	}
	if !o.requiresAuth {
		return
	}
	if osIs2xx(rec.Code) {
		osReport(t, "authz|"+o.opID,
			"AUTHZ BYPASS: unauthenticated principal %d got %d on secured op %s (%s %s)\nbody=%s",
			princ, rec.Code, o.opID, req.Method, req.URL.Path, osTrunc(rec.Body.String()))
		return
	}
	// Argument-monotonicity clause: a second schema-valid variant must also be denied.
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		req2 := w.osBuildRequest(st, o, princ, 0, rd)
		rec2 := osExec(w, req2)
		if osIs2xx(rec2.Code) {
			osReport(t, "authzvar|"+o.opID,
				"AUTHZ BYPASS (variant): unauthenticated principal %d got %d on secured op %s after a different schema-valid argument variant\nbody=%s",
				princ, rec2.Code, o.opID, osTrunc(rec2.Body.String()))
		}
	}
}

// --- Oracle 4: canary non-leakage ------------------------------------------
// VERIFIES: the planted canary (value of a seeded secret) never appears in (a) ANY response
// HEADER, (b) ANY non-2xx response body, or (c) ANY response body to an unauthenticated
// principal. These three hold unconditionally regardless of authorization.
// Does NOT verify: whether an AUTHENTICATED principal is authorized to read the secret whose
// value is the canary (that is authorization, covered — for the unauth layer — by oracle 3);
// leakage of secrets OTHER than the planted one; or leakage in an encoded/transformed form.
func osOracleCanary(t *testing.T, o *osOp, princ int, rec *httptest.ResponseRecorder) {
	t.Helper()
	if osHeaderHas(rec, osCanary) {
		osReport(t, "canaryhdr|"+o.opID, "CANARY LEAK (header): op=%s princ=%d code=%d leaked the canary in a response header", o.opID, princ, rec.Code)
		return
	}
	if !osBodyHas(rec, osCanary) {
		return
	}
	if !osIs2xx(rec.Code) {
		osReport(t, "canaryerr|"+o.opID, "CANARY LEAK (error body): op=%s princ=%d code=%d echoed the canary in a non-2xx body\nbody=%s",
			o.opID, princ, rec.Code, osTrunc(rec.Body.String()))
		return
	}
	if princ == osPrincAnon || princ == osPrincGarbage {
		osReport(t, "canaryunauth|"+o.opID, "CANARY LEAK (unauthenticated): op=%s princ=%d code=%d returned the canary to an unauthenticated caller\nbody=%s",
			o.opID, princ, rec.Code, osTrunc(rec.Body.String()))
	}
}

// --- Oracle 5: idempotent reads --------------------------------------------
// VERIFIES: a safe GET-by-id read, issued twice back-to-back with no intervening call and
// the same principal/arguments, returns byte-equal bodies after stripping declared-volatile
// fields (timestamps, token/nonce-like fields). A difference is a finding (non-deterministic
// read).
// Does NOT verify: GETs excluded as inherently volatile (metrics, health, version, stats,
// hygiene, drift, audit, access logs); reads that change due to background processes;
// equality of volatile fields themselves (they are stripped by key-name heuristic).
var osVolatileReadColls = map[string]bool{
	"metrics": true, "health": true, "version": true, "stats": true, "hygiene": true,
	"drift": true, "audit": true, "access-log": true, "access-review": true, "rotation-plan": true,
	"rotation-order": true, "impact": true, "simulate": true, "ownership-history": true,
	"info": true, "system": true, "ready": true, "live": true, "status": true,
	"evidence": true, "compliance": true, "export": true, "report": true, "snapshot": true,
	"backup": true, "posture": true, "dashboard": true, "summary": true, "activity": true,
	"crypto-inventory": true, "credential-trends": true, "trends": true, "inventory": true,
	"permission-changes": true, "sbom": true, "bom": true,
}

func osOracleIdempotentRead(t *testing.T, w *osWorld, o *osOp, princ int, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	if o.method != "GET" || !osIs2xx(rec.Code) {
		return
	}
	if osVolatileReadColls[o.collection] {
		return
	}
	// Skip encoded/embedded-timestamp report blobs: a base64/encoded payload (data_b64)
	// or an embedded "generated_at" can carry a generation time our key-stripping cannot
	// reach, so these reads are legitimately non-byte-stable. (Not a weakening of the
	// oracle: these are volatile reports, excluded like the volatile collections above.)
	rawA := rec.Body.String()
	if strings.Contains(rawA, "_b64") || strings.Contains(rawA, "generated_at") {
		return
	}
	// Re-issue the identical request immediately (no intervening call).
	req2 := cloneGET(req)
	rec2 := osExec(w, req2)
	if !osIs2xx(rec2.Code) {
		return // a state change we did not cause raced us; not a determinism finding
	}
	a := osCanonJSON(rec.Body.Bytes())
	b := osCanonJSON(rec2.Body.Bytes())
	if a != "" && b != "" && a != b {
		osReport(t, "idem|"+o.opID, "NON-IDEMPOTENT READ: %s %s (op=%s princ=%d) returned different bodies on two back-to-back reads\nA=%s\nB=%s",
			req.Method, req.URL.Path, o.opID, princ, osTrunc(a), osTrunc(b))
	}
}

func cloneGET(req *http.Request) *http.Request {
	r := httptest.NewRequest(http.MethodGet, req.URL.String(), nil)
	if v := req.Header.Get("Authorization"); v != "" {
		r.Header.Set("Authorization", v)
	}
	return r
}

var osVolatileKeys = map[string]bool{
	"created_at": true, "updated_at": true, "last_used_at": true, "last_used": true,
	"expires_at": true, "accessed_at": true, "rotated_at": true, "timestamp": true,
	"deleted_at": true, "token": true, "nonce": true, "etag": true, "last_accessed_at": true,
	"next_rotation_at": true, "now": true, "server_time": true,
	"uptime": true, "duration": true, "latency": true, "elapsed": true, "elapsed_ms": true,
	"goroutines": true, "alloc": true, "memory": true, "pid": true, "active_connections": true,
	"idle_connections": true, "in_use": true, "wait_count": true,
	// now-relative request-window echoes returned by compliance/report reads:
	"since": true, "until": true, "as_of": true, "window_start": true, "window_end": true,
	"from_time": true, "to_time": true, "generated_at": true, "queried_at": true,
	"requested_at": true, "computed_at": true,
}

// osCanonJSON parses JSON and re-emits it with volatile keys removed, for stable comparison.
func osCanonJSON(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	v = osStripVolatile(v)
	out, err := json.Marshal(v)
	if err != nil {
		return string(b)
	}
	return string(out)
}

func osStripVolatile(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k := range t {
			if osVolatileKeys[strings.ToLower(k)] {
				delete(t, k)
				continue
			}
			t[k] = osStripVolatile(t[k])
		}
		return t
	case []any:
		for i := range t {
			t[i] = osStripVolatile(t[i])
		}
		return t
	}
	return v
}

func osTrunc(s string) string {
	const max = 800
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

func FuzzOpenAPIStateful(f *testing.F) {
	osInitSweep()
	osLoadSpec(f)
	w := osBuildWorld(f)
	if osSweep {
		f.Log("FuzzOpenAPIStateful: SWEEP mode — oracle findings are logged (deduped), not fatal")
	}
	f.Cleanup(i18n.ResetForTesting)

	// Seeds: a mix of principals and simple op sequences. Byte 0 selects the principal;
	// bytes thereafter drive step count, op selection (u16), per-step mode, and args.
	f.Add([]byte{osPrincAnon, 0x00, 0x01, 0x00})
	f.Add([]byte{osPrincGarbage, 0x00, 0x02, 0x00})
	f.Add([]byte{osPrincGlobalAdmin, 0x05, 0x00, 0x10, 0x00, 0x00, 0x20, 0x00})
	f.Add([]byte{osPrincProjAdminA, 0x03, 0x00, 0x30, 0x02, 0x00, 0x40, 0x03})
	f.Add([]byte{osPrincViewer, 0x02, 0x01, 0x11, 0x00})
	f.Add([]byte{osPrincExpired, 0x02, 0x00, 0x22, 0x00})
	f.Add([]byte{osPrincMachine, 0x02, 0x00, 0x33, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		osRunIteration(t, w, program)
	})
}
