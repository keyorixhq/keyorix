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

// TestAuthzParity_HTTPvsGRPC_ShareCreate pins the SAME authorization decision across
// HTTP and gRPC for creating a secret share — a two-layer gate: both surfaces require
// secrets.write at the secret's project (route/method) AND core enforces owner-only
// sharing. The standout case is a project-WRITER (secrets.write on the project) who
// does NOT own the secret: it must NOT be able to re-share it (an escalation/IDOR
// vector) — on either surface. A divergence here is exploitable.
func TestAuthzParity_HTTPvsGRPC_ShareCreate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_journal_mode=WAL"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.ShareRecord{},
	))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "AdminPass123!",
	})
	require.NoError(t, err)

	var editorRole models.Role // editor = secrets.read + secrets.write
	require.NoError(t, db.Where("name = ?", "editor").First(&editorRole).Error)

	login := func(username, password string) string {
		s, _, lerr := c.Login(ctx, &core.LoginRequest{Username: username, Password: password})
		require.NoError(t, lerr)
		return s.SessionToken
	}

	// owner — has secrets.write on p1 AND owns the secret (can share).
	owner, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "owner", Email: "owner@example.com", Password: "OwnerPass123!"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: owner.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)
	ownerToken := login("owner", "OwnerPass123!")

	// writer — has secrets.write on p1 but does NOT own the secret (must not re-share).
	writer, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "writer", Email: "writer@example.com", Password: "WriterPass123!"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: writer.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)
	writerToken := login("writer", "WriterPass123!")

	// Recipients just need to exist. Distinct ones for the allow case so the HTTP and
	// gRPC shares don't collide as duplicates.
	require.NoError(t, db.Create(&models.User{ID: 500, Username: "rcpt-http", Email: "rh@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 501, Username: "rcpt-grpc", Email: "rg@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 502, Username: "rcpt-deny", Email: "rd@example.com"}).Error)

	// The secret, owned by owner in project 1.
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "shared-sec", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: owner.ID, CreatedBy: "owner",
	})
	require.NoError(t, err)

	shareSvc := services.NewShareService(c)
	gctx := func(userID uint, name string) context.Context {
		return context.WithValue(ctx, interceptors.GetUserContextKey(),
			&interceptors.UserContext{UserID: userID, Username: name})
	}

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := srv.Client()

	httpShare := func(token string, secretID, recipientID uint) bool {
		body, _ := json.Marshal(map[string]any{"recipient_id": recipientID, "is_group": false, "permission": "read"})
		r, _ := http.NewRequest("POST", srv.URL+fmt.Sprintf("/api/v1/secrets/%d/share", secretID), bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(r)
		require.NoError(t, derr)
		_ = resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
	grpcShare := func(ctx context.Context, secretID, recipientID uint) bool {
		_, gerr := shareSvc.ShareSecret(ctx, &pb.ShareSecretRequest{
			SecretId: uint32(secretID), RecipientId: uint32(recipientID), Permission: "read", IsGroup: false,
		})
		return gerr == nil
	}

	cases := []struct {
		name        string
		httpAllowed bool
		grpcAllowed bool
		wantAllowed bool
	}{
		{
			name:        "owner shares its own secret (has secrets.write + ownership)",
			httpAllowed: httpShare(ownerToken, sec.ID, 500),
			grpcAllowed: grpcShare(gctx(owner.ID, "owner"), sec.ID, 501),
			wantAllowed: true,
		},
		{
			name:        "project-writer re-shares a secret it does NOT own",
			httpAllowed: httpShare(writerToken, sec.ID, 502),
			grpcAllowed: grpcShare(gctx(writer.ID, "writer"), sec.ID, 502),
			wantAllowed: false,
		},
	}

	for _, tc := range cases {
		require.Equal(t, tc.wantAllowed, tc.httpAllowed, "%s: HTTP decision", tc.name)
		require.Equal(t, tc.wantAllowed, tc.grpcAllowed, "%s: gRPC decision", tc.name)
		require.Equal(t, tc.httpAllowed, tc.grpcAllowed, "%s: HTTP and gRPC must agree", tc.name)
	}
}
