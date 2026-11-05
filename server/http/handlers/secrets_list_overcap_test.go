// secrets_list_overcap_test.go — GET /api/v1/secrets answers a share fetch at the
// storage row cap with the same typed 422 the share lists use (STORAGE-ERR-CLASS-5).
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// cappedShareFetchStorage answers the caller's share fetch with a list at the
// 10000-row storage cap, which core refuses as possibly truncated.
func cappedShareFetchStorage(inner corestorage.Storage) corestorage.Storage {
	return storagetest.Hooked(inner, &storagetest.StoreHooks{
		ListSharesByUser: func(corestorage.Storage, context.Context, uint, time.Time) ([]*models.ShareRecord, error) {
			const atCap = 10000 // core.maxShareViewBatchSize, and the storage list cap
			shares := make([]*models.ShareRecord, atCap)
			for i := range shares {
				shares[i] = &models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read"}
			}
			return shares, nil
		},
	})
}

// TestListSecrets_OverCapShareFetchIsTyped422: every human-principal path of
// GET /api/v1/secrets that fetches the caller's shares maps ErrShareListOverCap to
// 422 ShareListOverCap (the body GET /shares answers), not 500 InternalError.
func TestListSecrets_OverCapShareFetchIsTyped422(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_list_overcap_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretACL{}, &models.AuditEvent{}, &models.SecretVersion{},
		&models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{},
	))
	proj := &models.Project{Name: "proj-cap"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-cap", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "cap-secret", ProjectID: proj.ID, EnvironmentID: env.ID, OwnerID: 7, Type: "static",
	}).Error)
	require.NoError(t, db.Create(&models.User{ID: 7, Username: "capped", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 8, Username: "norole", AccountState: "active"}).Error)
	roleID := seedReadRole(t, db, "cap_global_reader")
	require.NoError(t, db.Create(&models.UserRole{UserID: 7, RoleID: roleID}).Error)

	h, err := NewSecretHandler(core.NewKeyorixCore(cappedShareFetchStorage(store.NewLocalStorage(db))))
	require.NoError(t, err)

	scoped := fmt.Sprintf("/api/v1/secrets?project_id=%d", proj.ID)
	for name, tc := range map[string]struct {
		url    string
		userID uint
		user   string
	}{
		"scoped, role-authorized": {scoped, 7, "capped"},
		"unscoped, global reader": {"/api/v1/secrets", 7, "capped"},
		"unscoped, no role":       {"/api/v1/secrets", 8, "norole"},
	} {
		w := httptest.NewRecorder()
		h.ListSecrets(w, withUserCtxID2(httptest.NewRequest(http.MethodGet, tc.url, nil), tc.userID, tc.user))
		require.Equal(t, http.StatusUnprocessableEntity, w.Code, "%s: %s", name, w.Body.String())
		require.Contains(t, w.Body.String(), "ShareListOverCap", name)
		require.NotContains(t, w.Body.String(), "cap-secret", "%s: no list data on a refusal", name)
	}
}
