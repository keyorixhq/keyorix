package handlers

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// TestCreateUser_BaselineRoleCeiling: every new user receives the
// system_viewer baseline, so the creating actor must hold that role's
// permissions on every creation path — admin-set password, one-time password
// and setup link — as the project-assignment path already requires. An actor
// holding users.write but not system.read is refused (403) and no account is
// created; one that also holds system.read succeeds.
func TestCreateUser_BaselineRoleCeiling(t *testing.T) {
	h, db, writerOnly, writerWithBaseline, _ := setupBaselineCeilingWorld(t)

	paths := []struct{ name, extra string }{
		{"admin-set password", `,"password":"Str0ng#Pass!word-long"`},
		{"one-time password", `,"generate_one_time_password":true`},
		{"setup link", `,"deliver_setup_link":true`},
	}
	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			refused := "refused" + itoa(uint(i))
			w := postCreateUserAsUser(t, h, createBody(refused, p.extra), writerOnly)
			require.Equal(t, http.StatusForbidden, w.Code, "actor without the baseline role's permissions (body not printed: it may carry a one-time password or setup link)")
			require.False(t, userExists(t, db, refused), "a refused creation must not leave an account behind")

			allowed := "allowed" + itoa(uint(i))
			w = postCreateUserAsUser(t, h, createBody(allowed, p.extra), writerWithBaseline)
			require.Equal(t, http.StatusCreated, w.Code, "actor holding the baseline role's permissions")
			require.True(t, userExists(t, db, allowed))
		})
	}
}

// TestCreateUser_BaselineRoleCeiling_StorageFaultIs503: a storage failure while
// reading the system_viewer role for the baseline check answers 503
// storage_unavailable on every creation path (STORAGE-ERR-CLASS), not 500, and
// creates no account.
func TestCreateUser_BaselineRoleCeiling_StorageFaultIs503(t *testing.T) {
	h, db, _, writerWithBaseline, faulty := setupBaselineCeilingWorld(t)

	paths := []struct{ name, extra string }{
		{"admin-set password", `,"password":"Str0ng#Pass!word-long"`},
		{"one-time password", `,"generate_one_time_password":true`},
		{"setup link", `,"deliver_setup_link":true`},
	}
	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			username := "faulted" + itoa(uint(i))
			faulty.Arm(&faultstorage.FaultSpec{Method: "GetRoleByName", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			defer faulty.Arm(nil)
			w := postCreateUserAsUser(t, h, createBody(username, p.extra), writerWithBaseline)
			require.True(t, faulty.Fired(), "the baseline check's role read must be the faulted call")
			require.Equal(t, http.StatusServiceUnavailable, w.Code, "storage fault during the baseline check (body not printed: it may carry a one-time password or setup link)")
			assert.Contains(t, w.Body.String(), storageUnavailableCode)
			assert.NotEmpty(t, w.Header().Get("Retry-After"))
			assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "the driver cause must not reach the client")
			require.False(t, userExists(t, db, username), "a refused creation must not leave an account behind")
		})
	}
}

func createBody(username, extra string) string {
	return `{"username":"` + username + `","email":"` + username + `@example.invalid","display_name":"` + username + `"` + extra + `}`
}

func userExists(t *testing.T, db *gorm.DB, username string) bool {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.User{}).Where("username = ?", username).Count(&n).Error)
	return n > 0
}

// setupBaselineCeilingWorld builds the production schema and seeded roles,
// then two creating actors whose ONLY grant is a custom global role:
// users.read+users.write, and the same plus system.read (system_viewer's
// permission). The core runs over a FaultyStorage that is transparent until
// armed. Synthetic names and passwords only.
func setupBaselineCeilingWorld(t *testing.T) (h *UserHandler, db *gorm.DB, writerOnly, writerWithBaseline uint, faulty *faultstorage.FaultyStorage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, i18n.InitializeForTesting())
	db = fuzzworld.OpenSQLite(t, filepath.Join(t.TempDir(), "kx.db"), 1)
	fuzzworld.Bootstrap(t, db)
	faulty = faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := core.NewKeyorixCore(faulty)
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

	h, err = NewUserHandler(c)
	require.NoError(t, err)
	return h, db, writerOnly, writerWithBaseline, faulty
}
