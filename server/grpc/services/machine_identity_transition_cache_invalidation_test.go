// machine_identity_transition_cache_invalidation_test.go — regression coverage
// for the GRPC-track Finding #1 shape: a machine token revoked or suspended
// via the gRPC TransitionMachineIdentity RPC must stop authenticating over
// HTTP on the very next request, not linger in the middleware's positive auth
// cache for up to validTokenTTL (30s).
//
// The underlying eviction (core.TransitionMachineIdentity calling
// invalidateTokenCache after committing the state change — see
// internal/core/machine_identities.go, #r124) is transport-agnostic: it fires
// regardless of which transport drove the transition. But nothing previously
// exercised it starting from the REAL gRPC entry point
// (MachineIdentityGRPCService.TransitionMachineIdentity) and then checking the
// REAL HTTP middleware — this locks that specific cross-transport path in,
// the same way auth_cache_invalidation_test.go locks in the PAT/session leg.
package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// newMachineCacheTestRig is newMachineTestRigWithDB plus the HTTP-auth-cache
// invalidator server/main.go wires at startup (SetTokenCacheInvalidator ->
// middleware.InvalidateTokenCacheByHash) — without this wiring, core-layer
// revocation cannot evict the middleware's positive cache, so mirroring
// production exactly is the point.
func newMachineCacheTestRig(t *testing.T) (*MachineIdentityGRPCService, *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{}, &models.Role{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "machine-admin"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error) // global grant
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	return NewMachineIdentityService(coreService), coreService
}

// machineAuthProbe drives a bearer-token request through the REAL
// middleware.Authentication (a genuine *core.KeyorixCore, not a fake
// validator), so the test exercises the exact cache-hit/miss/eviction logic
// production traffic uses for machine tokens.
func machineAuthProbe(c *core.KeyorixCore, token string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h := customMiddleware.Authentication(c)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestGRPCTransitionMachineIdentity_RevokeEvictsHTTPAuthCacheImmediately drives
// the REAL gRPC TransitionMachineIdentity RPC (not core.TransitionMachineIdentity
// directly) to revoke a machine identity, then asserts the SAME machine token
// is rejected on the very next HTTP request rather than being served from the
// middleware's up-to-30s positive cache. Before #r124 wired eviction into the
// shared core method, gRPC-originated transitions had no path to evict the
// HTTP-only cache (the HTTP handler's own eviction was a direct, transport-local
// call the gRPC service never had).
func TestGRPCTransitionMachineIdentity_RevokeEvictsHTTPAuthCacheImmediately(t *testing.T) {
	svc, coreService := newMachineCacheTestRig(t)
	ctx := authCtx(1, "admin")

	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "ci-runner", IdentityType: "ci",
	})
	require.NoError(t, err)

	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "deploy",
	})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(issued.GetToken(), "kx_machine_"))
	token := issued.GetToken()

	// Populate the positive cache with a real HTTP request.
	require.Equal(t, http.StatusOK, machineAuthProbe(coreService, token),
		"machine token should authenticate before revocation")

	// Revoke via the REAL gRPC entry point — the exact code path Finding #1 (GRPC
	// track step 0 inventory) concerned.
	_, err = svc.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: m.GetId(), Action: "revoke",
	})
	require.NoError(t, err)

	// Immediately (no sleep, no 30s wait): HTTP must reject it, not serve the
	// stale positive cache entry.
	assert.Equal(t, http.StatusUnauthorized, machineAuthProbe(coreService, token),
		"a machine token revoked via gRPC must be rejected by HTTP immediately, not served from the positive auth cache")
}

// TestGRPCTransitionMachineIdentity_SuspendEvictsHTTPAuthCacheImmediately is the
// suspend twin of the revoke test above — same gap, same fix, same shape.
func TestGRPCTransitionMachineIdentity_SuspendEvictsHTTPAuthCacheImmediately(t *testing.T) {
	svc, coreService := newMachineCacheTestRig(t)
	ctx := authCtx(1, "admin")

	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "ci-runner-2", IdentityType: "ci",
	})
	require.NoError(t, err)

	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "deploy",
	})
	require.NoError(t, err)
	token := issued.GetToken()

	require.Equal(t, http.StatusOK, machineAuthProbe(coreService, token),
		"machine token should authenticate before suspension")

	_, err = svc.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: m.GetId(), Action: "suspend",
	})
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, machineAuthProbe(coreService, token),
		"a machine token suspended via gRPC must be rejected by HTTP immediately, not served from the positive auth cache")
}
