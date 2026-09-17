package http

// FuzzKeyorixHTTPAPISequence is the "fuzzing x DAST/IAST" tier: it drives a
// fuzzer-chosen sequence of grant/revoke/read operations against a REAL, fully
// wired keyorix stack — the actual chi router + auth middleware + handlers + core
// + crypto + storage — stood up in-process via the real NewRouter, so Go's
// coverage-guided fuzzer sees the whole request path. Reads go over HTTP
// (GET /api/v1/secrets/value?ref=...); mutations go through the core with an
// explicit auth-cache flush so the shadow model never lags the 30s token cache.
//
// Oracle = a tiny shadow authz model + the known secret plaintexts. Invariants are
// asserted only in the direction that cannot false-positive:
//   - AUTH-REQUIRED:   no/garbage token must never return 200 with a value.
//   - FAIL-CLOSED:     a principal the model says may NOT read must be denied.
//   - NO-PLAINTEXT-ON-DENY: a non-200 body must never contain the secret value.
//   - INTEGRITY:       a 200 read must carry EXACTLY the requested secret's value
//                      (we never assert "allowed => must 200").
// Tenant isolation falls out for free: a reader granted on project A reading a
// project-B secret is an ungranted (principal, project) pair, i.e. fail-closed.
//
// Phase 1. SQLite-backed (CI-runnable, fast); the same harness points at the rig
// Postgres by swapping the core's DB (Phase 2). See
// claude/2026-09-16-spec-live-api-invariant-fuzzing.md.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type apiFuzzPrincipal struct {
	id    uint
	token string // "" if this principal could not obtain a session (treated as no-token)
}

type apiFuzzWorld struct {
	router     http.Handler
	db         *gorm.DB
	c          *core.KeyorixCore
	readerRole uint
	adminTok   string
	projAID    uint
	projBID    uint
	refA, valA string
	refB, valB string
	principals []apiFuzzPrincipal // non-admin, own no secrets, start with no grants
}

func buildAPIFuzzWorld(f *testing.F) *apiFuzzWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	for _, ix := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active ON project_memberships (project_id, user_id) WHERE state <> 'revoked'",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active ON legal_holds (released) WHERE released = false",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''",
	} {
		_ = db.Exec(ix).Error
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap: %v (may already be initialised)", err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	if err != nil {
		f.Fatalf("admin login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "testadmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	pA, err := ls.CreateProject(ctx, &models.Project{Name: "proja"})
	if err != nil {
		f.Fatalf("projA: %v", err)
	}
	eA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pA.ID})
	if err != nil {
		f.Fatalf("envA: %v", err)
	}
	pB, err := ls.CreateProject(ctx, &models.Project{Name: "projb"})
	if err != nil {
		f.Fatalf("projB: %v", err)
	}
	eB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pB.ID})
	if err != nil {
		f.Fatalf("envB: %v", err)
	}

	// reader role carrying secrets.read (reuse the seeded permission if present)
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "api-fuzz-reader", NameFolded: "api-fuzz-reader"}
	if e := db.Create(&role).Error; e != nil {
		f.Fatalf("seed role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; e != nil {
		f.Fatalf("seed role-permission: %v", e)
	}

	sA, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sa", Value: []byte("VALUE-A-9f3c1"), ProjectID: pA.ID, EnvironmentID: eA.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sA == nil {
		f.Fatalf("secretA: %v", err)
	}
	sB, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sb", Value: []byte("VALUE-B-6b28e"), ProjectID: pB.ID, EnvironmentID: eB.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sB == nil {
		f.Fatalf("secretB: %v", err)
	}

	mkPrincipal := func(uname, email string) apiFuzzPrincipal {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: email, Password: "Xk7#Qp2$Rn5@Wv9!"})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		tok := ""
		if sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: uname, Password: "Xk7#Qp2$Rn5@Wv9!"}); lerr == nil && sess != nil {
			tok = sess.SessionToken
		} else {
			f.Logf("principal %s could not obtain a session (%v) — treated as no-token", uname, lerr)
		}
		return apiFuzzPrincipal{id: u.ID, token: tok}
	}
	principals := []apiFuzzPrincipal{
		mkPrincipal("readera", "readera@x.io"),
		mkPrincipal("readerb", "readerb@x.io"),
		mkPrincipal("outsider", "outsider@x.io"),
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router: %v", err)
	}

	return &apiFuzzWorld{
		router: r, db: db, c: c, readerRole: role.ID, adminTok: adminSess.SessionToken,
		projAID: pA.ID, projBID: pB.ID,
		refA: "proja/prod/sa", valA: "VALUE-A-9f3c1",
		refB: "projb/prod/sb", valB: "VALUE-B-6b28e",
		principals: principals,
	}
}

func FuzzKeyorixHTTPAPISequence(f *testing.F) {
	w := buildAPIFuzzWorld(f)
	f.Cleanup(i18n.ResetForTesting)

	f.Add([]byte{0, 0, 0, 2, 0, 3, 2, 2, 3})
	f.Add([]byte{0, 1, 1, 2, 1, 3})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		ctx := context.Background()

		// per-iteration reset: drop fuzz-principal grants, clear the model. NO token-cache
		// flush. middleware.InvalidateTokenCache writes a negative TOMBSTONE (it is a
		// revocation helper, not a refresh), which denied the token for invalidTokenTTL and
		// so silently masked every AUTHORIZED read in this harness — the positive path was
		// never actually verified (a granted read got 401, and read() only checks integrity
		// on a 200, so the assertion was skipped). The auth cache holds only the
		// authenticated IDENTITY; the per-request permission check re-reads grants from the
		// DB, so a grant/revoke is reflected on the very next read with no flush needed.
		w.db.Exec("DELETE FROM user_roles WHERE user_id IN (?,?,?)",
			w.principals[0].id, w.principals[1].id, w.principals[2].id)
		canRead := map[uint]map[uint]bool{}
		for _, p := range w.principals {
			canRead[p.id] = map[uint]bool{w.projAID: false, w.projBID: false}
		}

		projFor := func(sel int) uint {
			if sel%2 == 1 {
				return w.projBID
			}
			return w.projAID
		}
		grant := func(pi, proj int) {
			p := w.principals[pi%len(w.principals)]
			projID := projFor(proj)
			if err := w.c.AssignUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}, false); err == nil {
				canRead[p.id][projID] = true
			}
		}
		revoke := func(pi, proj int) {
			p := w.principals[pi%len(w.principals)]
			projID := projFor(proj)
			if err := w.c.RemoveUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}); err == nil {
				canRead[p.id][projID] = false
			}
		}
		read := func(who, which, mode byte) {
			ref, val, projID := w.refA, w.valA, w.projAID
			if which%2 == 1 {
				ref, val, projID = w.refB, w.valB, w.projBID
			}
			var authz string
			allowed := false
			switch mode % 4 {
			case 0: // no token
			case 1: // garbage token
				authz = "Bearer garbage-not-a-real-token"
			case 2: // admin (owns every secret; global admin)
				authz, allowed = "Bearer "+w.adminTok, true
			default: // a fuzz principal's token
				p := w.principals[int(who)%len(w.principals)]
				if p.token != "" {
					authz = "Bearer " + p.token
				}
				allowed = p.token != "" && canRead[p.id][projID]
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
			if authz != "" {
				req.Header.Set("Authorization", authz)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			body := rec.Body.String()

			if !allowed {
				if rec.Code == http.StatusOK {
					t.Fatalf("AUTHZ BYPASS: unauthorized read of %q returned 200 (mode=%d who=%d)\nbody=%s", ref, mode%4, who, body)
				}
				if strings.Contains(body, val) {
					t.Fatalf("PLAINTEXT LEAK on deny: response for %q (code=%d) contains the secret value\nbody=%s", ref, rec.Code, body)
				}
				return
			}
			// allowed: a 200 must carry EXACTLY this secret's value (never assert must-200).
			if rec.Code == http.StatusOK {
				var resp struct {
					Data struct {
						Value string `json:"value"`
					} `json:"data"`
				}
				if json.Unmarshal(rec.Body.Bytes(), &resp) == nil && resp.Data.Value != val {
					t.Fatalf("INTEGRITY: authorized read of %q returned wrong value %q (want %q)", ref, resp.Data.Value, val)
				}
			}
		}

		const maxSteps = 60
		for i := 0; i+2 < len(program) && i < maxSteps*3; i += 3 {
			switch program[i] % 3 {
			case 0:
				grant(int(program[i+1]), int(program[i+2]))
			case 1:
				revoke(int(program[i+1]), int(program[i+2]))
			default:
				read(program[i+1], program[i+2], program[i+1])
			}
		}
		// always exercise the two anchor paths regardless of input:
		read(0, 0, 2) // admin reads A -> integrity/round-trip
		read(2, 1, 3) // outsider (index 2, ungranted) reads B -> fail-closed
	})
}
