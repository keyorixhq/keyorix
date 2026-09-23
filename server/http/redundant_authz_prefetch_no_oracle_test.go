// redundant_authz_prefetch_no_oracle_test.go — pins the anti-enumeration
// invariant (403-for-both, #1645) across the three handlers touched by the
// fix/redundant-authz-prefetch cleanup (REST DeleteSecret, gRPC DeleteSecret,
// gRPC GetSecretVersions): a fully-unauthorized caller must get a
// byte-identical response for an existing-but-inaccessible secret and a
// nonexistent one. This is a structural guard on the INVARIANT, not on the
// prefetch fix itself — an unauthorized caller never reaches the prefetch at
// all (the route middleware / authorizeSecretScoped gate rejects first, see
// each subtest's own comment), so the prefetch's own replacement (a
// *WithPermissionCheck read swapped for a plain read) cannot change this
// either way. The point of committing this test is to make that structural
// fact machine-checked rather than merely asserted in a PR description.
package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// nonexistentSecretID is never created by this test's fixture — comfortably
// beyond any ID GORM's autoincrement would assign here.
const nonexistentSecretID = 999888777

// setupNoOracleFixture bootstraps a core with an admin-owned secret in one
// project, and an "attacker" user holding NO role, share, or ACL anywhere —
// not even in the secret's own project. Returns the core, the secret's ID,
// and the attacker's UserContext for both transports.
func setupNoOracleFixture(t *testing.T) (c *core.KeyorixCore, secretID uint, attackerID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_journal_mode=WAL")), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	c = core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	var admin models.User
	require.NoError(t, db.Where("username = ?", "admin").First(&admin).Error)

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "target", Value: []byte("v1"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: admin.ID, CreatedBy: "admin",
	})
	require.NoError(t, err)

	// The attacker: a real, authenticated user with zero grants anywhere —
	// no project role, no share, no ACL, no global permission. This is the
	// population handleScopeResolutionError/authorizeScopedTarget's
	// "AuthorizedAtGlobalScope" check must say no to, for BOTH the
	// existing-secret and nonexistent-secret branches to collapse to the
	// same response.
	attacker, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "attacker", Email: "attacker@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	return c, secret.ID, attacker.ID
}

// TestNoExistenceOracle_RESTDeleteSecret: an unauthorized DELETE on an
// existing secret and on a nonexistent one must be byte-identical. Both
// requests are rejected by the route's RequireScopedSecretPermission
// middleware (server/middleware/auth.go's handleScopeResolutionError /
// finishScopedPermissionRequest) BEFORE SecretHandler.DeleteSecret's body —
// and therefore its GetSecretWithPermissionCheck prefetch — ever runs.
func TestNoExistenceOracle_RESTDeleteSecret(t *testing.T) {
	c, secretID, attackerID := setupNoOracleFixture(t)
	ctx := context.Background()
	session, _, err := c.Login(ctx, &core.LoginRequest{Username: "attacker", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	_ = attackerID

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := srv.Client()

	doDelete := func(id uint) (int, string) {
		req, rerr := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/secrets/%d", srv.URL, id), nil)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+session.SessionToken)
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		defer resp.Body.Close()
		body, rderr := io.ReadAll(resp.Body)
		require.NoError(t, rderr)
		return resp.StatusCode, string(body)
	}

	existingStatus, existingBody := doDelete(secretID)
	nonexistentStatus, nonexistentBody := doDelete(nonexistentSecretID)

	require.Equal(t, existingStatus, nonexistentStatus, "status must not distinguish existing-inaccessible from nonexistent")
	require.Equal(t, existingBody, nonexistentBody, "body must not distinguish existing-inaccessible from nonexistent")
	// Sanity: confirm this is actually a denial, not an accidental 2xx that
	// would make the equality check vacuous.
	require.True(t, existingStatus == http.StatusForbidden || existingStatus == http.StatusNotFound,
		"expected a denial status, got %d", existingStatus)

	// Confirm the secret was NOT actually deleted (the attacker was denied,
	// not silently allowed).
	_, gerr := c.GetSecret(ctx, secretID)
	require.NoError(t, gerr, "the existing secret must still exist — the attacker's delete must have been denied, not applied")
}

// TestNoExistenceOracle_GRPCDeleteSecret: gRPC mirror of the REST case above.
// Both requests are rejected by authorizeSecretScoped -> authorizeScopedTarget
// (server/grpc/services/conversions.go) before SecretGRPCService.DeleteSecret's
// body — and its GetSecretWithPermissionCheck prefetch — ever runs.
func TestNoExistenceOracle_GRPCDeleteSecret(t *testing.T) {
	c, secretID, attackerID := setupNoOracleFixture(t)
	ctx := context.Background()
	actx := context.WithValue(ctx, interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: attackerID, Username: "attacker"})

	grpcSvc := services.NewSecretService(c)

	doDelete := func(id uint) (uint32, string) {
		_, err := grpcSvc.DeleteSecret(actx, &pb.DeleteSecretRequest{Id: uint32(id)})
		require.Error(t, err, "an unauthorized delete must be denied")
		st, ok := status.FromError(err)
		require.True(t, ok, "expected a gRPC status error")
		return uint32(st.Code()), st.Message()
	}

	existingCode, existingMsg := doDelete(secretID)
	nonexistentCode, nonexistentMsg := doDelete(nonexistentSecretID)

	require.Equal(t, existingCode, nonexistentCode, "gRPC code must not distinguish existing-inaccessible from nonexistent")
	require.Equal(t, existingMsg, nonexistentMsg, "gRPC message must not distinguish existing-inaccessible from nonexistent")

	_, gerr := c.GetSecret(ctx, secretID)
	require.NoError(t, gerr, "the existing secret must still exist — the attacker's delete must have been denied, not applied")
}

// TestNoExistenceOracle_GRPCGetSecretVersions: gRPC mirror for GetSecretVersions.
// authorizeSecretScoped runs at the top of SecretGRPCService.GetSecretVersions,
// before GetSecretVersionsWithPermissionCheck or the audit-only
// GetSecretWithPermissionCheck prefetch.
func TestNoExistenceOracle_GRPCGetSecretVersions(t *testing.T) {
	c, secretID, attackerID := setupNoOracleFixture(t)
	actx := context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: attackerID, Username: "attacker"})

	grpcSvc := services.NewSecretService(c)

	doGet := func(id uint) (uint32, string, bool) {
		resp, err := grpcSvc.GetSecretVersions(actx, &pb.GetSecretVersionsRequest{Id: uint32(id)})
		require.Error(t, err, "an unauthorized version-history read must be denied")
		st, ok := status.FromError(err)
		require.True(t, ok, "expected a gRPC status error")
		return uint32(st.Code()), st.Message(), resp != nil
	}

	existingCode, existingMsg, existingRespNonNil := doGet(secretID)
	nonexistentCode, nonexistentMsg, nonexistentRespNonNil := doGet(nonexistentSecretID)

	require.Equal(t, existingCode, nonexistentCode, "gRPC code must not distinguish existing-inaccessible from nonexistent")
	require.Equal(t, existingMsg, nonexistentMsg, "gRPC message must not distinguish existing-inaccessible from nonexistent")
	require.False(t, existingRespNonNil, "a denied call must not return a non-nil response")
	require.False(t, nonexistentRespNonNil, "a denied call must not return a non-nil response")
}
