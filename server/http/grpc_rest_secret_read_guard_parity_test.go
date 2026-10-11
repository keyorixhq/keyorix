package http

// grpc_rest_secret_read_guard_parity_test.go — INV-GRPC-01 (#2520).
//
// Invariant: gRPC cannot bypass a secret-read control that HTTP enforces.
// ADR-105 §"What is not wrong" established this by a one-off manual trace
// (gRPC GetSecretValue → core.GetSecretValueWithPermissionCheck →
// getSecretValueForUser → enforceSecretReadGuards): the read guards live in
// internal/core, so every transport inherits them. Nothing re-ran that trace —
// a refactor that moved a guard behind a transport-specific wrapper (into an
// HTTP handler or middleware) would leave gRPC open with every test green.
//
// This automates the trace as behaviour. For each guard enforceSecretReadGuards
// applies — expiry, suspension, restricted-classification MFA step-up, access
// schedule — a fresh secret is first read successfully over every value path
// on both transports (so a later denial is attributable to the guard, not to
// the secret or the principal), the guard condition is then applied, and every
// path must deny without disclosing the plaintext:
//
//	REST  GET /api/v1/secrets/value?ref=…         (GetSecretValueByRef)
//	REST  GET /api/v1/secrets/{id}?include_value=true
//	gRPC  SecretService/GetSecretValue
//
// for BOTH principal kinds, because the transports branch on them: a human
// session (super_admin, so RBAC never denies and only the guard can) reaches
// GetSecretValueWithPermissionCheck, and a machine token holding secrets.read
// reaches GetSecretValue / GetSecretValueResolved.
//
// Relationship to FuzzGRPCRESTSecretReadAuthzParity: that fuzzer varies GRANTS
// and the account-state gate; it never puts a secret into any of these guard
// states. This is the deterministic complement, not a duplicate.
//
// Scope, stated so its silence is not over-read: only the value-disclosing
// read paths above. gRPC has no by-version value read, share read, or bulk
// export; those HTTP-only paths are out of scope for a cross-transport check.
// The access-schedule case relies on a schedule window that is closed at every
// hour (StartHour == EndHour == 0), so it is wall-clock independent.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

type guardParityWorld struct {
	router  http.Handler
	grpc    pb.SecretServiceClient
	db      *gorm.DB
	c       *core.KeyorixCore
	adminID uint
	projID  uint
	envID   uint
	tokens  map[string]string // principal label → bearer token
}

func buildGuardParityWorld(t *testing.T) *guardParityWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{Logger: logger.Discard})
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1) // services write audit/access rows in detached goroutines
	}
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	// Gate 3 of the restricted-classification check. Only secrets classified
	// "restricted" are affected; the other cases' secrets are unclassified.
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 5)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "guardadmin", Email: "guardadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "guardadmin", Password: "TestPassword123!"})
	require.NoError(t, err)
	admin, err := ls.GetUserByUsername(ctx, "guardadmin")
	require.NoError(t, err)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "guardproj"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)

	// Machine principal holding exactly secrets.read at the project.
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		require.NoError(t, db.Create(&perm).Error)
	}
	role := models.Role{Name: "guard-reader", NameFolded: "guard-reader"}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	m, err := c.CreateMachineIdentity(ctx, proj.ID, "guard-bot", "service", "", "", admin.ID, 0)
	require.NoError(t, err)
	require.NoError(t, c.AssignMachineRole(ctx, m.ID, role.ID, core.Scope{ProjectID: proj.ID}, admin.ID, false))
	mtok, err := c.IssueMachineToken(ctx, proj.ID, m.ID, admin.ID, core.IssueMachineTokenParams{Name: "guard"})
	require.NoError(t, err)

	r, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	require.NoError(t, err)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &guardParityWorld{
		router: r, grpc: pb.NewSecretServiceClient(conn), db: db, c: c,
		adminID: admin.ID, projID: proj.ID, envID: env.ID,
		tokens: map[string]string{"session": adminSess.SessionToken, "machine": mtok.PlainToken},
	}
}

// readPath is one value-disclosing read: it returns whether the call succeeded
// and the plaintext it disclosed ("" if none).
type readPath struct {
	name string
	read func(token string, sec *models.SecretNode) (bool, string)
}

func (w *guardParityWorld) readPaths() []readPath {
	rest := func(token, url string, extract func([]byte) string) (bool, string) {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		if rec.Code < 200 || rec.Code >= 300 {
			return false, ""
		}
		return true, extract(rec.Body.Bytes())
	}
	return []readPath{
		{"REST GET /secrets/value?ref=", func(token string, sec *models.SecretNode) (bool, string) {
			return rest(token, "/api/v1/secrets/value?ref=guardproj/prod/"+sec.Name, func(b []byte) string {
				var resp struct {
					Data struct {
						Value string `json:"value"`
					} `json:"data"`
				}
				_ = json.Unmarshal(b, &resp)
				return resp.Data.Value
			})
		}},
		{"REST GET /secrets/{id}?include_value=true", func(token string, sec *models.SecretNode) (bool, string) {
			return rest(token, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sec.ID), func(b []byte) string {
				var resp struct {
					Data struct {
						Value string `json:"value"`
					} `json:"data"`
				}
				_ = json.Unmarshal(b, &resp)
				return resp.Data.Value
			})
		}},
		{"gRPC SecretService/GetSecretValue", func(token string, sec *models.SecretNode) (bool, string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
			resp, err := w.grpc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: uint32(sec.ID), IncludeValue: true})
			if err != nil {
				return false, ""
			}
			return true, resp.GetValue()
		}},
	}
}

func TestSecretReadGuards_DenyIdenticallyOverGRPCAndREST(t *testing.T) {
	w := buildGuardParityWorld(t)
	ctx := context.Background()

	guards := []struct {
		name  string
		apply func(t *testing.T, sec *models.SecretNode)
	}{
		{"expired", func(t *testing.T, sec *models.SecretNode) {
			// Raw write on purpose (simulate a not-yet-swept expiry); `past` is UTC so
			// BeforeSave's normalization would be a no-op. Allowlisted in g1619.
			past := time.Now().UTC().Add(-time.Hour)
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).Update("expiration", past).Error)
		}},
		{"suspended", func(t *testing.T, sec *models.SecretNode) {
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).Update("status", core.SecretStatusSuspended).Error)
		}},
		{"restricted, MFA step-up required", func(t *testing.T, sec *models.SecretNode) {
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).Update("classification", core.ClassificationRestricted).Error)
		}},
		{"outside access schedule", func(t *testing.T, sec *models.SecretNode) {
			require.NoError(t, w.db.Create(&models.SecretAccessSchedule{
				SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 0, Timezone: "UTC",
			}).Error)
		}},
	}

	n := 0
	for _, g := range guards {
		for _, principal := range []string{"session", "machine"} {
			t.Run(g.name+"/"+principal, func(t *testing.T) {
				n++
				plaintext := fmt.Sprintf("GUARD-PARITY-%d-7c1e", n)
				sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
					Name: fmt.Sprintf("guarded%d", n), Value: []byte(plaintext),
					ProjectID: w.projID, EnvironmentID: w.envID,
					Type: "password", CreatedBy: "guardadmin", OwnerID: w.adminID,
				})
				require.NoError(t, err)
				token := w.tokens[principal]

				for _, p := range w.readPaths() {
					ok, val := p.read(token, sec)
					require.Truef(t, ok, "precondition: %s must read the unguarded secret (else a later denial proves nothing)", p.name)
					require.Equalf(t, plaintext, val, "precondition: %s must return the plaintext", p.name)
				}

				g.apply(t, sec)

				decisions := map[string]bool{}
				for _, p := range w.readPaths() {
					ok, val := p.read(token, sec)
					decisions[p.name] = ok
					assert.Falsef(t, ok, "%s ALLOWED a read the %q guard must deny — the guard is not enforced on this transport", p.name, g.name)
					assert.NotContainsf(t, val, plaintext, "%s disclosed the plaintext of a %q secret", p.name, g.name)
				}
				t.Logf("decisions after guard: %v", decisions)
			})
		}
	}
}
