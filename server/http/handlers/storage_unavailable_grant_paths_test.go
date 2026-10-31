package handlers

// storage_unavailable_grant_paths_test.go — STORAGE-ERR-CLASS-2 item 2 (REST).
//
// Grant / create paths read a parent (project, environment, role, secret) and used to
// answer a read FAULT with the verdict for an absent parent (404 "Project not found",
// 400 "unknown role", 409 "no longer exists", 500). They fail closed either way; the
// fault is now 503 storage_unavailable + Retry-After so the caller retries instead of
// "fixing" a request that was fine. A true not-found keeps its status.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// sweepREST arms an error on the 1st, 2nd, ... call of method and runs the handler
// once per arming until the call count is exhausted. A fault must never come back as
// one of foldedStatuses (the verdict for an absent parent); the count of 503
// storage_unavailable answers is returned so the caller can require the site was hit.
func sweepREST(t *testing.T, faulty *faultstorage.FaultyStorage, method string, foldedStatuses []int, call func() *httptest.ResponseRecorder) (unavailable int) {
	t.Helper()
	defer faulty.Arm(nil)
	for nth := 1; nth <= 12; nth++ {
		faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindError, Err: assert.AnError})
		w := call()
		if !faulty.Fired() {
			return unavailable
		}
		if w.Code == http.StatusServiceUnavailable {
			var body suErrBody
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, storageUnavailableCode, body.Error)
			assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
			assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "the driver cause must not reach the client")
			unavailable++
			continue
		}
		assert.NotContains(t, foldedStatuses, w.Code, "%s fault #%d answered the absent-parent verdict %d: %s", method, nth, w.Code, w.Body.String())
	}
	return unavailable
}

func TestStorageUnavailable_GrantPathsREST(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxgrantpaths_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	local := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(local, nil)
	cs := core.NewKeyorixCore(faulty)

	// User 1 (the identity withUserCtx presents) holds a global bypass role.
	ctx := t.Context()
	admin, err := local.CreateUser(ctx, &models.User{
		Username: "gp-admin", UsernameFolded: "gp-admin", Email: "gp-admin@example.com", EmailFolded: "gp-admin@example.com",
		IsActive: true, AccountState: "active",
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, admin.ID, "withUserCtx authenticates as user 1")
	rn, err := identity.NewFoldedName("gp-bypass")
	require.NoError(t, err)
	bypass, err := local.CreateRole(ctx, rn, "")
	require.NoError(t, err)
	require.NoError(t, local.SetRoleBypassesPermissionChecks(ctx, bypass.ID, true))
	require.NoError(t, local.AssignRole(ctx, admin.ID, bypass.ID, corestorage.Scope{}))

	proj := &models.Project{Name: "gp-proj"}
	require.NoError(t, db.Create(proj).Error)
	srcEnv := &models.Environment{ProjectID: proj.ID, Name: "gp-src"}
	require.NoError(t, db.Create(srcEnv).Error)
	dstEnv := &models.Environment{ProjectID: proj.ID, Name: "gp-dst"}
	require.NoError(t, db.Create(dstEnv).Error)
	pid := suID(proj.ID)

	cat := NewCatalogHandler(cs)
	secrets, err := NewSecretHandler(cs)
	require.NoError(t, err)
	users, err := NewUserHandler(cs)
	require.NoError(t, err)

	t.Run("create environment", func(t *testing.T) {
		n := 0
		call := func() *httptest.ResponseRecorder {
			n++
			w := httptest.NewRecorder()
			cat.CreateProjectEnvironment(w, suReq(http.MethodPost, `{"name":"gp-env-`+strconv.Itoa(n)+`"}`, map[string]string{"id": pid}))
			return w
		}
		assert.GreaterOrEqual(t, sweepREST(t, faulty, "GetProject", []int{http.StatusNotFound, http.StatusBadRequest}, call), 2,
			"both the handler's own project pre-check and core's are classified")
		w := httptest.NewRecorder()
		cat.CreateProjectEnvironment(w, suReq(http.MethodPost, `{"name":"gp-env-absent"}`, map[string]string{"id": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404")
		assert.Empty(t, w.Header().Get("Retry-After"))
		assert.Equal(t, http.StatusCreated, call().Code, "the retried create succeeds")
	})

	t.Run("copy environment secrets", func(t *testing.T) {
		call := func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			secrets.CopyEnvironmentSecrets(w, suReq(http.MethodPost, `{"target_environment_id":`+suID(dstEnv.ID)+`}`,
				map[string]string{"id": pid, "envId": suID(srcEnv.ID)}))
			return w
		}
		assert.GreaterOrEqual(t, sweepREST(t, faulty, "GetEnvironment", []int{http.StatusBadRequest, http.StatusNotFound}, call), 1)
		w := httptest.NewRecorder()
		secrets.CopyEnvironmentSecrets(w, suReq(http.MethodPost, `{"target_environment_id":`+suID(dstEnv.ID)+`}`,
			map[string]string{"id": pid, "envId": "9999999"}))
		assert.Equal(t, http.StatusBadRequest, w.Code, "an absent source environment stays the 400 validation answer")
		assert.Equal(t, http.StatusOK, call().Code, "the retried copy succeeds")
	})

	t.Run("create user with a system role", func(t *testing.T) {
		n := 0
		call := func() *httptest.ResponseRecorder {
			n++
			name := "gp-user-" + strconv.Itoa(n)
			body := `{"username":"` + name + `","email":"` + name + `@example.com","display_name":"GP","password":"Correct-Horse-Battery-9","role":"gp-bypass"}`
			w := httptest.NewRecorder()
			users.CreateUser(w, suReq(http.MethodPost, body, nil))
			return w
		}
		assert.GreaterOrEqual(t, sweepREST(t, faulty, "GetRoleByName", []int{http.StatusBadRequest, http.StatusNotFound}, call), 1)
		w := httptest.NewRecorder()
		users.CreateUser(w, suReq(http.MethodPost,
			`{"username":"gp-absent","email":"gp-absent@example.com","display_name":"GP","password":"Correct-Horse-Battery-9","role":"no-such-role"}`, nil))
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusForbidden, "an absent role stays a 4xx verdict, got %d: %s", w.Code, w.Body.String())
		assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("resolve secret access request", func(t *testing.T) {
		secret := &models.SecretNode{ProjectID: proj.ID, EnvironmentID: srcEnv.ID, Name: "gp-secret", IsSecret: true}
		require.NoError(t, db.Create(secret).Error)
		n := 0
		call := func() *httptest.ResponseRecorder {
			n++
			req := &models.AccessRequest{ProjectID: proj.ID, UserID: 100 + uint(n), SecretID: &secret.ID, State: core.AccessRequestPending, CreatedAt: time.Now()}
			require.NoError(t, db.Create(req).Error)
			w := httptest.NewRecorder()
			cat.ResolveSecretAccessRequest(w, suReq(http.MethodPut, `{"action":"approve"}`, map[string]string{"requestId": suID(req.ID)}))
			return w
		}
		assert.GreaterOrEqual(t, sweepREST(t, faulty, "GetSecret", []int{http.StatusConflict, http.StatusNotFound}, call), 1)
		assert.GreaterOrEqual(t, sweepREST(t, faulty, "GetAccessRequest", []int{http.StatusConflict, http.StatusNotFound}, call), 1)
		w := httptest.NewRecorder()
		cat.ResolveSecretAccessRequest(w, suReq(http.MethodPut, `{"action":"approve"}`, map[string]string{"requestId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404: %s", w.Body.String())
		assert.True(t, strings.Contains(w.Body.String(), "not found"))
	})
}
