package http

// grpc_rest_authz_parity_fuzz_test.go — FuzzGRPCRESTSecretReadAuthzParity.
//
// A DIFFERENTIAL authz fuzzer across transports. keyorix serves the same product
// over REST (server/http, NewRouter) and gRPC (server/grpc, NewServer) — both
// delegating to one KeyorixCore. The business logic can't diverge; what can is the
// per-surface AUTHZ wiring (each transport re-installs the PAT restriction, the
// session tag, and resolves its own (permission, scope) before calling core). The
// gRPC auth interceptor is littered with "parity with HTTP" / "not bypassable by
// switching transport" — a hand-maintained invariant across two code paths. This
// target makes that invariant machine-checked.
//
// For one fuzzed grant configuration + principal + target secret, it reads the SAME
// secret over BOTH transports with the SAME credential and asserts:
//
//   - DECISION PARITY: REST allowed == gRPC allowed. A mismatch is a
//     transport-dependent authorization decision — an auth bypass on the more
//     permissive surface.
//   - VALUE PARITY: when both allow, both return exactly the secret's plaintext.
//
// The oracle is sound: the two transports are each other's oracle (no shadow model,
// no "must accept"). The only care needed is (a) giving both surfaces genuinely
// identical inputs — same token bytes, same secret (REST by ref, gRPC by the same
// secret's id) — and (b) flushing the REST auth cache after every grant/revoke so a
// 30s-stale REST decision can't masquerade as a divergence (gRPC has no auth cache).
//
// Both surfaces are the REAL production wiring (NewRouter / NewServer) over one
// shared in-memory core — CI-runnable, no external deps. Novel fuzzer #4, Phase 1
// (secret read). See claude/2026-09-17-spec-grpc-rest-authz-parity-differential.md.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

type parityPrincipal struct {
	id    uint
	token string // "" if no session could be obtained (treated as no-token)
}

type paritySecret struct {
	ref, val string
	id       uint
	projID   uint
}

// parityCreateSeq gives every create-parity attempt a process-unique name so the two
// transports never collide and a soak never re-uses a name. atomic: fuzz workers run parallel.
var parityCreateSeq atomic.Int64

type parityWorld struct {
	router     http.Handler
	grpc       pb.SecretServiceClient
	db         *gorm.DB
	c          *core.KeyorixCore
	readerRole uint
	writerRole uint // carries secrets.write, for the create-authz parity check
	adminTok   string
	projAID    uint
	projBID    uint
	envAID     uint
	envBID     uint
	secA, secB paritySecret
	principals []parityPrincipal
}

func buildParityWorld(f *testing.F) *parityWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1) // serialize: services write audit/access rows in detached goroutines
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	for _, ix := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active ON project_memberships (project_id, user_id) WHERE state <> 'revoked'",
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

	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "parity-reader", NameFolded: "parity-reader"}
	if e := db.Create(&role).Error; e != nil {
		f.Fatalf("seed role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; e != nil {
		f.Fatalf("seed role-permission: %v", e)
	}

	// writer role carrying secrets.write, for the create-authz parity check.
	var writePerm models.Permission
	if e := db.Where("name = ?", "secrets.write").First(&writePerm).Error; e != nil {
		writePerm = models.Permission{Name: "secrets.write", Resource: "secrets", Action: "write"}
		if e2 := db.Create(&writePerm).Error; e2 != nil {
			f.Fatalf("seed write permission: %v", e2)
		}
	}
	writeRole := models.Role{Name: "parity-writer", NameFolded: "parity-writer"}
	if e := db.Create(&writeRole).Error; e != nil {
		f.Fatalf("seed write role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: writeRole.ID, PermissionID: writePerm.ID}).Error; e != nil {
		f.Fatalf("seed write role-permission: %v", e)
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

	mkPrincipal := func(uname, email string) parityPrincipal {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: email, Password: "Xk7#Qp2$Rn5@Wv9!"})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		tok := ""
		if sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: uname, Password: "Xk7#Qp2$Rn5@Wv9!"}); lerr == nil && sess != nil {
			tok = sess.SessionToken
		} else {
			f.Logf("principal %s could not obtain a session (%v)", uname, lerr)
		}
		return parityPrincipal{id: u.ID, token: tok}
	}
	principals := []parityPrincipal{
		mkPrincipal("readera", "readera@x.io"),
		mkPrincipal("readerb", "readerb@x.io"),
		mkPrincipal("outsider", "outsider@x.io"),
	}

	// REST surface: the real chi router.
	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router: %v", err)
	}

	// gRPC surface: the real server (all services + real auth interceptor) on bufconn.
	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	if err != nil {
		f.Fatalf("grpc server: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	f.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		f.Fatalf("grpc dial: %v", err)
	}
	f.Cleanup(func() { _ = conn.Close() })

	return &parityWorld{
		router: r, grpc: pb.NewSecretServiceClient(conn), db: db, c: c,
		readerRole: role.ID, writerRole: writeRole.ID, adminTok: adminSess.SessionToken,
		projAID: pA.ID, projBID: pB.ID, envAID: eA.ID, envBID: eB.ID,
		secA:       paritySecret{ref: "proja/prod/sa", val: "VALUE-A-9f3c1", id: sA.ID, projID: pA.ID},
		secB:       paritySecret{ref: "projb/prod/sb", val: "VALUE-B-6b28e", id: sB.ID, projID: pB.ID},
		principals: principals,
	}
}

func FuzzGRPCRESTSecretReadAuthzParity(f *testing.F) {
	w := buildParityWorld(f)
	f.Cleanup(i18n.ResetForTesting)

	f.Add([]byte{0, 0, 0, 2, 0, 3, 2, 2, 3})
	f.Add([]byte{0, 1, 1, 2, 1, 3})
	f.Add([]byte{3, 0, 0, 4, 3, 0}) // grant-write p0@projA, then create as p0 -> both allow
	f.Add([]byte{4, 3, 0})          // create as ungranted p0 -> both deny
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		ctx := context.Background()

		// Per-iteration reset: drop fuzz-principal grants. No token-cache flush — the
		// middleware's positive cache holds only the authenticated IDENTITY (which never
		// changes); the per-request permission check re-reads grants from the DB, so a
		// grant/revoke is seen immediately on both surfaces. (InvalidateTokenCache writes a
		// negative TOMBSTONE that would make REST deny a still-valid token — a false
		// divergence from gRPC, which has no auth cache.)
		w.db.Exec("DELETE FROM user_roles WHERE user_id IN (?,?,?)",
			w.principals[0].id, w.principals[1].id, w.principals[2].id)

		projFor := func(sel int) uint {
			if sel%2 == 1 {
				return w.projBID
			}
			return w.projAID
		}
		grant := func(pi, proj int) {
			p := w.principals[pi%len(w.principals)]
			_ = w.c.AssignUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projFor(proj)}, false)
		}
		revoke := func(pi, proj int) {
			p := w.principals[pi%len(w.principals)]
			_ = w.c.RemoveUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projFor(proj)})
		}
		envFor := func(sel int) uint {
			if sel%2 == 1 {
				return w.envBID
			}
			return w.envAID
		}
		grantWrite := func(pi, proj int) {
			p := w.principals[pi%len(w.principals)]
			_ = w.c.AssignUserRole(ctx, 0, p.id, w.writerRole, core.Scope{ProjectID: projFor(proj)}, false)
		}

		// restRead returns (allowed, value). allowed == the reveal endpoint returned the value.
		restRead := func(token, ref string) (bool, string) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				return false, ""
			}
			var resp struct {
				Data struct {
					Value string `json:"value"`
				} `json:"data"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			return true, resp.Data.Value
		}

		// grpcRead returns (allowed, value). allowed == GetSecretValue succeeded.
		grpcRead := func(token string, id uint) (bool, string) {
			gctx := context.Background()
			if token != "" {
				gctx = metadata.NewOutgoingContext(gctx, metadata.Pairs("authorization", "Bearer "+token))
			}
			resp, err := w.grpc.GetSecretValue(gctx, &pb.GetSecretRequest{Id: uint32(id), IncludeValue: true})
			if err != nil {
				return false, ""
			}
			return true, resp.GetValue()
		}

		// readParity drives BOTH surfaces with the same token+secret and asserts parity.
		readParity := func(tokLabel, token string, sec paritySecret) {
			restOK, restVal := restRead(token, sec.ref)
			grpcOK, grpcVal := grpcRead(token, sec.id)
			if restOK != grpcOK {
				t.Fatalf("AUTHZ PARITY VIOLATION reading %q as %s: REST allowed=%v, gRPC allowed=%v — a transport-dependent authorization decision",
					sec.ref, tokLabel, restOK, grpcOK)
			}
			if restOK && grpcOK {
				if restVal != sec.val {
					t.Fatalf("REST value integrity reading %q: got %q want %q", sec.ref, restVal, sec.val)
				}
				if grpcVal != sec.val {
					t.Fatalf("gRPC value integrity reading %q: got %q want %q", sec.ref, grpcVal, sec.val)
				}
			}
		}

		// createParity drives a secret CREATE over BOTH surfaces with the same principal +
		// project/env scope but DISTINCT names (authz is name-independent), and asserts the
		// allow/deny decision agrees. Both surfaces authorize via AuthorizePrincipal(
		// secrets.write, {project,env}) — REST inside the handler (the create route carries no
		// scoped-permission middleware), gRPC in the method — so a divergence is a real
		// transport-dependent write-authz bug. Distinct names avoid a duplicate-name confound;
		// created rows are dropped by name so a soak stays bounded.
		createParity := func(tokLabel, token string, proj int) {
			projID, envID := projFor(proj), envFor(proj)
			n := parityCreateSeq.Add(1)
			restName := fmt.Sprintf("pcp-rest-%d", n)
			grpcName := fmt.Sprintf("pcp-grpc-%d", n)

			body := fmt.Sprintf(`{"name":%q,"value":"v","project_id":%d,"environment_id":%d,"type":"password"}`, restName, projID, envID)
			rreq := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/", strings.NewReader(body))
			rreq.Header.Set("Content-Type", "application/json")
			if token != "" {
				rreq.Header.Set("Authorization", "Bearer "+token)
			}
			rrec := httptest.NewRecorder()
			w.router.ServeHTTP(rrec, rreq)

			gctx := context.Background()
			if token != "" {
				gctx = metadata.NewOutgoingContext(gctx, metadata.Pairs("authorization", "Bearer "+token))
			}
			_, gerr := w.grpc.CreateSecret(gctx, &pb.CreateSecretRequest{
				Name: grpcName, Value: "v", ProjectId: uint32(projID), EnvironmentId: uint32(envID), Type: "password",
			})

			// Bounded soak: drop whatever got created (targeted by the unique names).
			w.db.Exec("DELETE FROM secret_nodes WHERE name = ? OR name = ?", restName, grpcName)

			// Classify each surface into a clean authz DECISION or a THIRD outcome, and assert
			// parity ONLY on clean allow-vs-deny. A third outcome on either side (e.g. the gRPC
			// invalid-token rate-limiter returning ResourceExhausted, a validation error, an
			// internal error) is not an authorization decision and can legitimately differ
			// across transports, so it is skipped — that keeps the oracle sound (no false
			// positive). allow = the create was authorized (2xx / gRPC OK); deny = refused by
			// authn/authz (401,403 / Unauthenticated,PermissionDenied).
			restDec := "other"
			switch rrec.Code {
			case http.StatusOK, http.StatusCreated:
				restDec = "allow"
			case http.StatusUnauthorized, http.StatusForbidden:
				restDec = "deny"
			}
			grpcDec := "other"
			switch {
			case gerr == nil:
				grpcDec = "allow"
			case status.Code(gerr) == codes.Unauthenticated || status.Code(gerr) == codes.PermissionDenied:
				grpcDec = "deny"
			}
			if restDec == "other" || grpcDec == "other" {
				return
			}
			if restDec != grpcDec {
				t.Fatalf("CREATE AUTHZ PARITY VIOLATION as %s in project %d: REST=%s (code=%d), gRPC=%s (err=%v) — transport-dependent write authorization",
					tokLabel, projID, restDec, rrec.Code, grpcDec, gerr)
			}
		}

		secFor := func(sel byte) paritySecret {
			if sel%2 == 1 {
				return w.secB
			}
			return w.secA
		}
		tokenFor := func(mode, who byte) (string, string) {
			switch mode % 4 {
			case 0:
				return "no-token", ""
			case 1:
				return "garbage-token", "garbage-not-a-real-token"
			case 2:
				return "admin", w.adminTok
			default:
				p := w.principals[int(who)%len(w.principals)]
				return "principal", p.token
			}
		}

		const maxSteps = 40
		for i := 0; i+2 < len(program) && i < maxSteps*3; i += 3 {
			switch program[i] % 5 {
			case 0:
				grant(int(program[i+1]), int(program[i+2]))
			case 1:
				revoke(int(program[i+1]), int(program[i+2]))
			case 2:
				label, tok := tokenFor(program[i+1], program[i+2])
				readParity(label, tok, secFor(program[i+2]))
			case 3:
				grantWrite(int(program[i+1]), int(program[i+2]))
			default: // 4
				label, tok := tokenFor(program[i+1], program[i+2])
				createParity(label, tok, int(program[i+2]))
			}
		}
		// Anchors, every iteration regardless of input:
		readParity("admin", w.adminTok, w.secA)               // read: both allow
		readParity("outsider", w.principals[2].token, w.secB) // read: both deny (ungranted)
		readParity("no-token", "", w.secA)                    // read: both deny (unauthenticated)
		createParity("admin", w.adminTok, 0)                  // create: both allow (admin has write)
		createParity("outsider", w.principals[2].token, 0)    // create: both deny (no write grant)
		createParity("no-token", "", 0)                       // create: both deny (unauthenticated)
	})
}
