package services

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestUserService_CreateUser_BaselineRoleCeiling: every new user receives the
// system_viewer baseline, so the creating actor must hold that role's
// permissions on every creation path (admin-set password, one-time password,
// setup link). An actor holding users.write but not system.read is refused
// (PermissionDenied) and no account is created; one that also holds
// system.read succeeds.
func TestUserService_CreateUser_BaselineRoleCeiling(t *testing.T) {
	svc, db, writerOnly, writerWithBaseline := setupGRPCBaselineCeilingWorld(t)

	paths := []struct {
		name string
		set  func(*pb.CreateUserRequest)
	}{
		{"admin-set password", func(r *pb.CreateUserRequest) { pw := "Str0ng#Pass!word-long"; r.Password = &pw }},
		{"one-time password", func(r *pb.CreateUserRequest) { r.GenerateOneTimePassword = true }},
		{"setup link", func(r *pb.CreateUserRequest) { r.DeliverSetupLink = true }},
	}
	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			req := func(username string) *pb.CreateUserRequest {
				r := &pb.CreateUserRequest{Username: username, Email: username + "@example.invalid"}
				p.set(r)
				return r
			}
			refused := []string{"refused-pw", "refused-otp", "refused-link"}[i]
			_, err := svc.CreateUser(authCtx(writerOnly, "writer-only", "users.write"), req(refused))
			require.Equal(t, codes.PermissionDenied, status.Code(err), "actor without the baseline role's permissions: %v", err)
			require.False(t, grpcUserExists(t, db, refused), "a refused creation must not leave an account behind")

			allowed := []string{"allowed-pw", "allowed-otp", "allowed-link"}[i]
			_, err = svc.CreateUser(authCtx(writerWithBaseline, "writer-baseline", "users.write"), req(allowed))
			require.NoError(t, err, "actor holding the baseline role's permissions")
			require.True(t, grpcUserExists(t, db, allowed))
		})
	}
}

func grpcUserExists(t *testing.T, db *gorm.DB, username string) bool {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.User{}).Where("username = ?", username).Count(&n).Error)
	return n > 0
}

// setupGRPCBaselineCeilingWorld: production schema and seeded roles, then two
// creating actors whose ONLY grant is a custom global role: users.read+
// users.write, and the same plus system.read (system_viewer's permission).
// Synthetic names and passwords only.
func setupGRPCBaselineCeilingWorld(t *testing.T) (svc *UserGRPCService, db *gorm.DB, writerOnly, writerWithBaseline uint) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, i18n.InitializeForTesting())
	db = fuzzworld.OpenSQLite(t, filepath.Join(t.TempDir(), "kx.db"), 1)
	fuzzworld.Bootstrap(t, db)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetCredentialDelivery(nil, "https://keyorix.example.invalid")
	c.SetBootstrapToken("baseline-ceiling-bootstrap")
	const pw = "Az9!synthetic-only-Q7"
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "kxadmin", Email: "kxadmin@example.invalid", Password: pw, DisplayName: "Admin", Token: "baseline-ceiling-bootstrap",
	})
	require.NoError(t, err)

	permID := func(name string) uint {
		var p models.Permission
		require.NoError(t, db.Where("name = ?", name).First(&p).Error, "permission %s", name)
		return p.ID
	}
	mkRole := func(name string, perms ...string) uint {
		r := models.Role{Name: name, NameFolded: name, Description: "synthetic"}
		require.NoError(t, db.Create(&r).Error)
		for _, p := range perms {
			require.NoError(t, db.Create(&models.RolePermission{RoleID: r.ID, PermissionID: permID(p)}).Error)
		}
		return r.ID
	}
	mkActor := func(username string, roleID uint) uint {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: username, Email: username + "@example.invalid", DisplayName: username, Password: pw})
		require.NoError(t, err)
		// the custom role is the actor's only grant (drop the CreateUser baseline)
		require.NoError(t, db.Exec("DELETE FROM user_roles WHERE user_id = ?", u.ID).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: roleID}).Error)
		return u.ID
	}
	writerOnly = mkActor("writer-only", mkRole("user-writer", "users.read", "users.write"))
	writerWithBaseline = mkActor("writer-baseline", mkRole("user-writer-baseline", "users.read", "users.write", "system.read"))
	return NewUserService(c), db, writerOnly, writerWithBaseline
}
