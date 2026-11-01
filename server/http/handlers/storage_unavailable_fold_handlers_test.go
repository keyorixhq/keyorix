package handlers

// storage_unavailable_fold_handlers_test.go — ERR-FOLD-HANDLERS-1 (REST).
//
// Handlers that answered a storage read FAULT with the verdict for an absent target
// (404 "not found") by matching message text or by folding every error. The fault is
// now 503 storage_unavailable + Retry-After (or 500 where the surrounding code had no
// 503 mapping); a true not-found keeps its status.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// foldWorld is one SQLite database behind a FaultyStorage, with user 1 (the identity
// withUserCtx presents) holding a global bypass role.
type foldWorld struct {
	db     *gorm.DB
	local  *store.LocalStorage
	faulty *faultstorage.FaultyStorage
	cs     *core.KeyorixCore
	admin  *models.User
}

func newFoldWorld(t *testing.T) *foldWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxfoldh_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	local := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(local, nil)
	ctx := t.Context()
	admin, err := local.CreateUser(ctx, &models.User{
		Username: "fold-admin", UsernameFolded: "fold-admin", Email: "fold-admin@example.com", EmailFolded: "fold-admin@example.com",
		IsActive: true, AccountState: "active",
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, admin.ID, "withUserCtx authenticates as user 1")
	rn, err := identity.NewFoldedName("fold-bypass")
	require.NoError(t, err)
	bypass, err := local.CreateRole(ctx, rn, "")
	require.NoError(t, err)
	require.NoError(t, local.SetRoleBypassesPermissionChecks(ctx, bypass.ID, true))
	require.NoError(t, local.AssignRole(ctx, admin.ID, bypass.ID, corestorage.Scope{}))
	return &foldWorld{db: db, local: local, faulty: faulty, cs: core.NewKeyorixCore(faulty), admin: admin}
}

// requireFold503 asserts w is the 503 storage_unavailable answer.
func requireFold503(t *testing.T, w *httptest.ResponseRecorder, msgAndArgs ...any) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "%v: %s", msgAndArgs, w.Body.String())
	assert.Contains(t, w.Body.String(), storageUnavailableCode)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "the driver cause must not reach the client")
}

// foldAuthedServer serves h behind the real Authentication middleware on a core built
// over a FaultyStorage, bootstrapped with one admin whose session token it returns.
func foldAuthedServer(t *testing.T, method, pattern string, h http.HandlerFunc) (srv *httptest.Server, faulty *faultstorage.FaultyStorage, local *store.LocalStorage, token string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxfoldauth_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	local = store.NewLocalStorage(db)
	faulty = faultstorage.NewFaultyStorage(local, nil)
	cs := core.NewKeyorixCore(faulty)
	cs.SetBootstrapToken("fold-boot")
	_, err := cs.BootstrapSystem(t.Context(), &core.BootstrapRequest{
		Username: "foldadmin", Email: "foldadmin@example.com", Password: "Kx#Vr9$Mn2!Zp4@Qw", Token: "fold-boot",
	})
	require.NoError(t, err)
	session, _, err := cs.Login(t.Context(), &core.LoginRequest{Username: "foldadmin", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.MethodFunc(method, pattern, h)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, faulty, local, session.SessionToken
}

func foldDo(t *testing.T, srv *httptest.Server, method, path, token string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	_, _ = io.Copy(&sb, resp.Body)
	return resp.StatusCode, sb.String(), resp.Header
}

func (fw *foldWorld) secret(t *testing.T, name string) (*models.Project, *models.SecretNode) {
	t.Helper()
	p := &models.Project{Name: name + "-proj"}
	require.NoError(t, fw.db.Create(p).Error)
	env := &models.Environment{ProjectID: p.ID, Name: name + "-env"}
	require.NoError(t, fw.db.Create(env).Error)
	s, err := fw.local.CreateSecret(t.Context(), &models.SecretNode{
		Name: name, ProjectID: p.ID, EnvironmentID: env.ID, Type: "password",
		IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	return p, s
}

// item 1: secret access requests and anomaly acknowledge.
func TestFoldHandlers_Item1_SecretAccessRequestsAndAnomalyAck(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	cat := NewCatalogHandler(fw.cs)
	p, s := fw.secret(t, "fold1")
	sid := s.ID
	req := &models.AccessRequest{ProjectID: p.ID, UserID: fw.admin.ID, SecretID: &sid, State: core.AccessRequestPending, CreatedAt: time.Now()}
	require.NoError(t, fw.db.Create(req).Error)

	t.Run("GetSecretAccessRequest", func(t *testing.T) {
		fw.faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessRequest", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
		w := httptest.NewRecorder()
		cat.GetSecretAccessRequest(w, suReq(http.MethodGet, "", map[string]string{"requestId": suID(req.ID)}))
		require.True(t, fw.faulty.Fired())
		requireFold503(t, w, "GetAccessRequest fault")
		fw.faulty.Arm(nil)

		w = httptest.NewRecorder()
		cat.GetSecretAccessRequest(w, suReq(http.MethodGet, "", map[string]string{"requestId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404")
		w = httptest.NewRecorder()
		cat.GetSecretAccessRequest(w, suReq(http.MethodGet, "", map[string]string{"requestId": suID(req.ID)}))
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("CreateSecretAccessRequest pre-check", func(t *testing.T) {
		// User 1 holds a global bypass role, so the permission check passes through the RBAC
		// fallback; the share read happens first and a fault there must not read as a 404.
		for _, method := range []string{"ListSharesBySecret", "GetSecretAccessSchedule"} {
			fw.faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			w := httptest.NewRecorder()
			cat.CreateSecretAccessRequest(w, suReq(http.MethodPost, `{"secret_id":`+suID(s.ID)+`,"reason":"need it"}`, nil))
			require.True(t, fw.faulty.Fired(), method)
			requireFold503(t, w, method+" fault")
		}
		fw.faulty.Arm(nil)

		w := httptest.NewRecorder()
		cat.CreateSecretAccessRequest(w, suReq(http.MethodPost, `{"secret_id":9999999,"reason":"need it"}`, nil))
		assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404")
		assert.Empty(t, w.Header().Get("Retry-After"))
	})

	t.Run("AcknowledgeAnomalyAlert", func(t *testing.T) {
		srv, faulty, local, token := foldAuthedServer(t, http.MethodPost, "/anomalies/{id}/acknowledge", AcknowledgeAnomalyAlert)
		alert := &models.AnomalyAlert{AlertType: "off_hours", Severity: "low", DetectedAt: time.Now()}
		require.NoError(t, local.CreateAnomalyAlert(ctx, alert))
		path := "/anomalies/" + suID(alert.ID) + "/acknowledge"

		faulty.Arm(&faultstorage.FaultSpec{Method: "ListAnomalyAlerts", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
		code, body, hdr := foldDo(t, srv, http.MethodPost, path, token)
		require.True(t, faulty.Fired())
		require.Equal(t, http.StatusServiceUnavailable, code, body)
		assert.Contains(t, body, storageUnavailableCode)
		assert.NotEmpty(t, hdr.Get("Retry-After"))
		faulty.Arm(nil)

		code, _, _ = foldDo(t, srv, http.MethodPost, "/anomalies/9999999/acknowledge", token)
		assert.Equal(t, http.StatusNotFound, code, "a true not-found stays 404")
		code, _, _ = foldDo(t, srv, http.MethodPost, path, token)
		assert.Equal(t, http.StatusOK, code)
	})
}
