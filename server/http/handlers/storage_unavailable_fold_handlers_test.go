package handlers

// storage_unavailable_fold_handlers_test.go — ERR-FOLD-HANDLERS-1 (REST).
//
// Handlers that answered a storage read FAULT with the verdict for an absent target
// (404 "not found") by matching message text or by folding every error. The fault is
// now 503 storage_unavailable + Retry-After (or 500 where the surrounding code had no
// 503 mapping); a true not-found keeps its status.

import (
	"errors"
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

// item 2: access-review campaigns (JSON and CSV export).
func TestFoldHandlers_Item2_AccessReviewCampaigns(t *testing.T) {
	fw := newFoldWorld(t)
	cat := NewCatalogHandler(fw.cs)
	p := &models.Project{Name: "fold2-proj"}
	require.NoError(t, fw.db.Create(p).Error)
	camp := &models.AccessReviewCampaign{ProjectID: p.ID, Name: "q", State: core.CampaignStateOpen, CreatedBy: fw.admin.ID}
	require.NoError(t, fw.db.Create(camp).Error)
	params := func(campaignID uint) map[string]string {
		return map[string]string{"id": suID(p.ID), "campaignId": suID(campaignID)}
	}
	handlers := map[string]http.HandlerFunc{
		"GetAccessReviewCampaign":       cat.GetAccessReviewCampaign,
		"ExportAccessReviewCampaignCSV": cat.ExportAccessReviewCampaignCSV,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			fw.faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessReviewCampaign", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			w := httptest.NewRecorder()
			h(w, suReq(http.MethodGet, "", params(camp.ID)))
			require.True(t, fw.faulty.Fired())
			requireFold503(t, w, name)
			fw.faulty.Arm(nil)

			w = httptest.NewRecorder()
			h(w, suReq(http.MethodGet, "", params(9_999_999)))
			assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404: %s", w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"))
			w = httptest.NewRecorder()
			h(w, suReq(http.MethodGet, "", params(camp.ID)))
			assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		})
	}
}

// errFoldDriver is a storage fault whose driver text contains the words "not found":
// a text matcher would read it as a missing target.
var errFoldDriver = errors.New("driver: relation lookup failed, row not found in replica")

func (fw *foldWorld) armFault(method string, nth int, err error) {
	fw.faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindError, Err: err})
}

// requireNot404Fault asserts a fault answered neither 404 nor 2xx (the verdict for an
// absent target) and, when want503, that it is the storage_unavailable answer.
func requireNot404Fault(t *testing.T, w *httptest.ResponseRecorder, want503 bool, what string) {
	t.Helper()
	assert.NotEqual(t, http.StatusNotFound, w.Code, "%s: a storage fault answered \"not found\": %s", what, w.Body.String())
	assert.GreaterOrEqual(t, w.Code, 500, "%s: %s", what, w.Body.String())
	if want503 {
		requireFold503(t, w, what)
	}
	assert.NotContains(t, w.Body.String(), "driver:", what+": the driver cause must not reach the client")
}

// item 3: handler text-match families converted to errors.Is on a typed error.
func TestFoldHandlers_Item3_TextMatchFamilies(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	cat := NewCatalogHandler(fw.cs)
	p, s := fw.secret(t, "fold3")

	t.Run("notifications MarkRead", func(t *testing.T) {
		h := NewNotificationHandler(fw.cs)
		n := &models.Notification{UserID: fw.admin.ID, Title: "t", Message: "m"}
		require.NoError(t, fw.db.Create(n).Error)
		call := func(id uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.MarkRead(w, suReq(http.MethodPost, "", map[string]string{"id": suID(id)}))
			return w
		}
		fw.armFault("MarkNotificationRead", 1, errFoldDriver)
		requireNot404Fault(t, call(n.ID), false, "MarkNotificationRead fault")
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, call(9_999_999).Code, "a true not-found stays 404")
		assert.Equal(t, http.StatusOK, call(n.ID).Code)
	})

	t.Run("secret ACL revoke", func(t *testing.T) {
		h, err := NewSecretHandler(fw.cs)
		require.NoError(t, err)
		call := func(aclID string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.RevokeSecretACL(w, suReq(http.MethodDelete, "", map[string]string{"id": suID(s.ID), "aclId": aclID}))
			return w
		}
		fw.armFault("ListSecretACLs", 1, errFoldDriver)
		requireNot404Fault(t, call("1"), false, "ListSecretACLs fault")
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, call("9999999").Code, "a true not-found stays 404")
	})

	t.Run("risk exception approve", func(t *testing.T) {
		h := NewDashboardHandler(fw.cs)
		call := func(id string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.ApproveRiskException(w, suReq(http.MethodPost, "", map[string]string{"id": id}))
			return w
		}
		fw.armFault("GetRiskException", 1, errFoldDriver)
		requireNot404Fault(t, call("1"), false, "GetRiskException fault")
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, call("9999999").Code, "a true not-found stays 404")
	})

	t.Run("group members", func(t *testing.T) {
		h, err := NewGroupHandler(fw.cs)
		require.NoError(t, err)
		g, err := fw.local.CreateGroup(ctx, &models.Group{Name: "fold3-grp", NameFolded: "fold3-grp"})
		require.NoError(t, err)
		list := func(id string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.GetGroupMembers(w, suReq(http.MethodGet, "", map[string]string{"id": id}))
			return w
		}
		fw.armFault("ListGroupMembers", 1, errFoldDriver)
		requireNot404Fault(t, list(suID(g.ID)), false, "ListGroupMembers fault")
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, list("9999999").Code, "a true not-found stays 404")
		assert.Equal(t, http.StatusOK, list(suID(g.ID)).Code)

		add := func(groupID string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.AddGroupMember(w, suReq(http.MethodPost, `{"user_id":`+suID(fw.admin.ID)+`}`, map[string]string{"id": groupID}))
			return w
		}
		fw.armFault("AddUserToGroup", 1, errFoldDriver)
		requireNot404Fault(t, add(suID(g.ID)), false, "AddUserToGroup fault")
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, add("9999999").Code, "a true not-found stays 404")
	})

	t.Run("access review revoke and attest", func(t *testing.T) {
		// revoke: the group branch reads through c.storage (the share branch reads inside a
		// transaction the double cannot fault; its classification is unit-tested in core).
		g, err := fw.local.CreateGroup(ctx, &models.Group{Name: "fold3-rev", NameFolded: "fold3-rev"})
		require.NoError(t, err)
		revoke := func(groupID string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.RevokeProjectAccessReview(w, suReq(http.MethodPost,
				`{"source":"role","principal_type":"group","principal_id":`+groupID+`,"role_id":1}`, map[string]string{"id": suID(p.ID)}))
			return w
		}
		fw.armFault("GetGroup", 1, errFoldDriver)
		w := revoke(suID(g.ID))
		require.True(t, fw.faulty.Fired())
		requireFold503(t, w, "revoke GetGroup fault")
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, revoke("9999999").Code, "a true not-found stays 404")

		other, err := fw.local.CreateUser(ctx, &models.User{
			Username: "fold3-other", UsernameFolded: "fold3-other", Email: "fold3-other@example.com", EmailFolded: "fold3-other@example.com",
			IsActive: true, AccountState: "active",
		})
		require.NoError(t, err)
		attest := func(secretID string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.AttestProjectAccessReview(w, suReq(http.MethodPost,
				`{"source":"direct_share","principal_type":"user","principal_id":`+suID(other.ID)+`,"secret_id":`+secretID+`}`, map[string]string{"id": suID(p.ID)}))
			return w
		}
		fw.armFault("GetSecret", 1, errFoldDriver)
		w = attest(suID(s.ID))
		require.True(t, fw.faulty.Fired())
		requireFold503(t, w, "attest GetSecret fault")
		fw.faulty.Arm(nil)
		assert.Equal(t, http.StatusNotFound, attest("9999999").Code, "a true not-found stays 404")
	})

	t.Run("create folder", func(t *testing.T) {
		h := NewFolderHandler(fw.cs)
		var env models.Environment
		require.NoError(t, fw.db.First(&env, "project_id = ?", p.ID).Error)
		call := func(parent uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.CreateFolder(w, suReq(http.MethodPost, `{"name":"f","project_id":`+suID(p.ID)+`,"environment_id":`+suID(env.ID)+`,"parent_id":`+suID(parent)+`}`, nil))
			return w
		}
		fired := 0
		for nth := 1; nth <= 6; nth++ {
			fw.armFault("GetSecret", nth, errFoldDriver)
			w := call(s.ID)
			if !fw.faulty.Fired() {
				break
			}
			assert.NotEqual(t, http.StatusNotFound, w.Code, "GetSecret fault #%d answered not-found: %s", nth, w.Body.String())
			if w.Code == http.StatusServiceUnavailable {
				requireFold503(t, w, "GetSecret fault")
				fired++
			}
		}
		fw.faulty.Arm(nil)
		assert.GreaterOrEqual(t, fired, 1, "the parent-folder read is classified")
		w := call(9_999_999)
		assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "Parent folder not found")
	})

	t.Run("transition membership", func(t *testing.T) {
		m := &models.ProjectMembership{ProjectID: p.ID, UserID: fw.admin.ID, Role: "viewer", State: core.MembershipInvited, InvitedAt: time.Now()}
		require.NoError(t, fw.db.Create(m).Error)
		call := func(id uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.TransitionMembership(w, suReq(http.MethodPut, `{"action":"revoke"}`, map[string]string{"id": suID(p.ID), "membershipId": suID(id)}))
			return w
		}
		fw.armFault("GetProjectMembership", 1, errFoldDriver)
		requireFold503(t, call(m.ID), "GetProjectMembership fault")
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		w := call(9_999_999)
		assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404: %s", w.Body.String())
		assert.Equal(t, http.StatusOK, call(m.ID).Code)
	})
}

// item 5: secrets_copy.go answers a source read fault with 503, not 500.
func TestFoldHandlers_Item5_CopySecretSourceReadFault(t *testing.T) {
	fw := newFoldWorld(t)
	h, err := NewSecretHandler(fw.cs)
	require.NoError(t, err)
	p, s := fw.secret(t, "fold5")
	var env models.Environment
	require.NoError(t, fw.db.First(&env, "project_id = ?", p.ID).Error)
	dst := &models.Environment{ProjectID: p.ID, Name: "fold5-dst"}
	require.NoError(t, fw.db.Create(dst).Error)
	call := func(id uint) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.CopySecret(w, suReq(http.MethodPost, `{"environment_id":`+suID(dst.ID)+`}`, map[string]string{"id": suID(id)}))
		return w
	}
	fw.armFault("GetSecret", 1, assert.AnError)
	requireFold503(t, call(s.ID), "source GetSecret fault")
	require.True(t, fw.faulty.Fired())
	fw.faulty.Arm(nil)
	assert.Equal(t, http.StatusNotFound, call(9_999_999).Code, "a true not-found stays 404")
}
