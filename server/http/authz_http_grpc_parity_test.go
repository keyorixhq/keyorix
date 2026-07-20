package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestAuthzParity_HTTPvsGRPC_Secrets pins that the HTTP and gRPC surfaces reach the
// SAME authorization decision for the same operation, principal, and resource. Both
// paths funnel through core.AuthorizePrincipal, but they hardcode the required
// permission + scope independently (the HTTP route's RequireScopedPermission vs the
// gRPC service method) — so if one were ever changed to require a different (weaker or
// wrong-resource) permission, the two surfaces would diverge and this test would catch
// it. A divergence is an exploitable inconsistency, not just a missing test.
func TestAuthzParity_HTTPvsGRPC_Secrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_journal_mode=WAL")), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	// Bootstrap seeds the admin, the standard roles (incl. "viewer" = secrets.read) +
	// permissions, and project 1 with its environments.
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	var admin models.User
	require.NoError(t, db.Where("username = ?", "admin").First(&admin).Error)
	// A second project, isolated from the viewer's grant.
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 9, ProjectID: 2, Name: "prod"}).Error)

	// A viewer (secrets.read) scoped to project 1 ONLY.
	vu, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "viewer", Email: "viewer@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	var viewerRole models.Role
	require.NoError(t, db.Where("name = ?", "viewer").First(&viewerRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: vu.ID, RoleID: viewerRole.ID, ProjectID: 1}).Error)
	session, _, err := c.Login(ctx, &core.LoginRequest{Username: "viewer", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	token := session.SessionToken

	// Seed secrets (with a version each). S1 is OWNED by the viewer in project 1, so the
	// viewer's secrets.read on p1 + ownership grants read on both surfaces. S2 lives in
	// project 2 where the viewer has no grant at all.
	s1, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s1", Value: []byte("v1"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: vu.ID, CreatedBy: "viewer",
	})
	require.NoError(t, err)
	s2, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s2", Value: []byte("v2"), ProjectID: 2, EnvironmentID: 9,
		Type: "password", Classification: "internal", OwnerID: admin.ID, CreatedBy: "admin",
	})
	require.NoError(t, err)

	grpc := services.NewSecretService(c)
	vctx := context.WithValue(ctx, interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: vu.ID, Username: "viewer"})

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := srv.Client()

	// allowed == the surface granted the operation (2xx for HTTP, nil error for gRPC).
	httpAllowed := func(method, path string, body any) bool {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r, _ = http.NewRequest(method, srv.URL+path, bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r, _ = http.NewRequest(method, srv.URL+path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(r)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}

	createBody := func(projectID, envID uint) map[string]any {
		return map[string]any{"name": "newsec", "value": "x", "project_id": projectID, "environment_id": envID, "type": "password"}
	}

	cases := []struct {
		name        string
		httpAllowed bool
		grpcAllowed bool
		wantAllowed bool
	}{
		{
			name:        "read own secret in own project (viewer owns + has secrets.read on p1)",
			httpAllowed: httpAllowed("GET", fmt.Sprintf("/api/v1/secrets/%d", s1.ID), nil),
			grpcAllowed: granted(grpc.GetSecret(vctx, &pb.GetSecretRequest{Id: uint32(s1.ID)})),
			wantAllowed: true,
		},
		{
			name:        "read secret in other project (no grant on p2)",
			httpAllowed: httpAllowed("GET", fmt.Sprintf("/api/v1/secrets/%d", s2.ID), nil),
			grpcAllowed: granted(grpc.GetSecret(vctx, &pb.GetSecretRequest{Id: uint32(s2.ID)})),
			wantAllowed: false,
		},
		{
			name:        "create secret in own project (viewer lacks secrets.write)",
			httpAllowed: httpAllowed("POST", "/api/v1/secrets", createBody(1, 1)),
			grpcAllowed: granted(grpc.CreateSecret(vctx, &pb.CreateSecretRequest{Name: "newsec", Value: "x", ProjectId: 1, EnvironmentId: 1, Type: "password"})),
			wantAllowed: false,
		},
	}

	for _, tc := range cases {
		require.Equal(t, tc.wantAllowed, tc.httpAllowed, "%s: HTTP decision", tc.name)
		require.Equal(t, tc.wantAllowed, tc.grpcAllowed, "%s: gRPC decision", tc.name)
		require.Equal(t, tc.httpAllowed, tc.grpcAllowed, "%s: HTTP and gRPC must agree", tc.name)
	}
}

// granted turns a gRPC call's (result, error) into an "allowed" bool.
func granted(_ *pb.Secret, err error) bool { return err == nil }
