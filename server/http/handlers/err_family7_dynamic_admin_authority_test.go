package handlers

// CORE-ERR-FAMILY-7 item 1 (REST side): POST /dynamic-secrets/configs by a caller who holds
// secrets.write but not admin authority (#162) answered 400 with the generic "internal
// error" text, because the refusal was untyped. It is 403 now. A storage fault while
// resolving the caller's roles is the shared 503 storage_unavailable.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func errFamily7CreateConfig(h *DynamicSecretHandler, userID uint, name string) *httptest.ResponseRecorder {
	body := bytes.NewBufferString(`{"name":"` + name + `","project_id":1,"environment_id":10,"backend_type":"postgres","admin_dsn":"postgres://a@db.example/x"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", body)
	uc := &middleware.UserContext{UserID: userID, Username: "u", ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
	r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.CreateConfig(w, r)
	return w
}

// errFamily7DynamicCore is a core over st with a fake credential engine, so the create
// reaches the #162 admin check (it runs after the backend-type check).
func errFamily7DynamicCore(st storage.Storage) *core.KeyorixCore {
	cs := core.NewKeyorixCore(st)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	cs.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	return cs
}

func TestErrFamily7_CreateDynamicConfigWithoutAdminAuthorityIs403(t *testing.T) {
	_, _, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}))
	perm := &models.Permission{Name: "secrets.write", Resource: "secrets", Action: "write"}
	require.NoError(t, db.Create(perm).Error)
	writer := &models.Role{Name: "writer-only"}
	require.NoError(t, db.Create(writer).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writer.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "writer", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: writer.ID}).Error)
	h := NewDynamicSecretHandler(errFamily7DynamicCore(store.NewLocalStorage(db)))

	w := errFamily7CreateConfig(h, 2, "refused")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var count int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&count).Error)
	assert.Zero(t, count, "a refused create writes no config")
}

func TestErrFamily7_CreateDynamicConfigAuthorityReadFaultIs503(t *testing.T) {
	_, _, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}))
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewDynamicSecretHandler(errFamily7DynamicCore(faulty))

	// Count the admin-flag reads of a create that gets past the #162 check (it may still
	// fail later, at the encryption step: this fixture has no encryptor). The last read is
	// the #162 check; the earlier ones belong to the secrets.write authorization.
	_ = errFamily7CreateConfig(h, 1, "dry-run")
	n := 0
	for _, c := range faulty.Calls() {
		if c.Method == "RoleSetBypassesPermissionChecks" {
			n++
		}
	}
	require.Positive(t, n, "the admin check must read the admin flag")

	faulty.Arm(&faultstorage.FaultSpec{Method: "RoleSetBypassesPermissionChecks", NthCall: n, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := errFamily7CreateConfig(h, 1, "faulted")
	require.True(t, faulty.Fired(), "the admin-authority read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)
}
