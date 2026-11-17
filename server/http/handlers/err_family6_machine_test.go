package handlers

// err_family6_machine_test.go — CORE-ERR-FAMILY-6 item 4 (REST).
//
// The machine-identity, machine-token, OIDC-binding and machine role-binding handlers
// classified core's refusals by looking for words in the message. They now read the
// sentinels core types them with. What changes for a client:
//
//   - a read fault while resolving the environment or role of a role binding is 503
//     (it was 404 when the driver text said "not found", 500 otherwise);
//   - a role the actor cannot grant is 403 (it was 500);
//   - a config or lease that is gone, or an input core refuses, is 404 / 400 on the
//     dynamic-secret routes (it was 502).

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestErrFamily6_Item4_MachineRoleBinding(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	cat := NewCatalogHandler(fw.cs)

	proj := &models.Project{Name: "fam6-m-proj"}
	require.NoError(t, fw.db.Create(proj).Error)
	otherProj := &models.Project{Name: "fam6-m-other"}
	require.NoError(t, fw.db.Create(otherProj).Error)
	env := &models.Environment{ProjectID: proj.ID, Name: "fam6-m-env"}
	require.NoError(t, fw.db.Create(env).Error)
	foreignEnv := &models.Environment{ProjectID: otherProj.ID, Name: "fam6-m-foreign"}
	require.NoError(t, fw.db.Create(foreignEnv).Error)
	rn, err := identity.NewFoldedName("fam6-m-role")
	require.NoError(t, err)
	role, err := fw.local.CreateRole(ctx, rn, "")
	require.NoError(t, err)
	m, err := fw.cs.CreateMachineIdentity(ctx, proj.ID, "fam6-machine", "service", "", "", fw.admin.ID, 0)
	require.NoError(t, err)

	pid, mid, rid := suID(proj.ID), suID(m.ID), suID(role.ID)
	params := map[string]string{"id": pid, "machineId": mid}
	grant := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		cat.GrantMachineRole(w, suReq(http.MethodPost, body, params))
		return w
	}
	remove := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": mid, "roleId": rid})
		r.URL.RawQuery = query
		cat.RemoveMachineRole(w, r)
		return w
	}
	envBody := func(envID uint) string {
		return `{"role_id":` + rid + `,"environment_id":` + strconv.FormatUint(uint64(envID), 10) + `}`
	}

	t.Run("a read fault resolving the environment is 503, even when its text says not found", func(t *testing.T) {
		armFamily6(fw, "GetEnvironment")
		w := grant(envBody(env.ID))
		require.True(t, fw.faulty.Fired())
		requireFold503(t, w, "GetEnvironment fault")
		fw.faulty.Arm(nil)
	})
	t.Run("a read fault resolving the role is 503, even when its text says not found", func(t *testing.T) {
		armFamily6(fw, "GetRole")
		w := grant(`{"role_id":` + rid + `}`)
		require.True(t, fw.faulty.Fired())
		requireFold503(t, w, "GetRole fault")
		fw.faulty.Arm(nil)
	})
	t.Run("a missing environment is 404, one of another project is 400", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, grant(envBody(9999999)).Code)
		assert.Equal(t, http.StatusBadRequest, grant(envBody(foreignEnv.ID)).Code)
	})
	t.Run("a missing role is 404", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, grant(`{"role_id":9999999}`).Code)
	})
	t.Run("grant, duplicate grant, remove, remove again", func(t *testing.T) {
		w := grant(`{"role_id":` + rid + `}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, http.StatusConflict, grant(`{"role_id":`+rid+`}`).Code, "already assigned")
		require.Equal(t, http.StatusOK, remove("").Code)
		// A role the machine does not hold is 404, like DELETE /user-roles and gRPC
		// RemoveRole (#4020 parity; decided 2026-11-13, FIX-ERRMAP-STRUCT-1).
		assert.Equal(t, http.StatusNotFound, remove("").Code, "not assigned")
	})
	t.Run("an unknown machine is 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		cat.GrantMachineRole(w, suReq(http.MethodPost, `{"role_id":`+rid+`}`, map[string]string{"id": pid, "machineId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestErrFamily6_Item4_OIDCBindingsAndMigrate(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	cat := NewCatalogHandler(fw.cs)

	proj := &models.Project{Name: "fam6-o-proj"}
	require.NoError(t, fw.db.Create(proj).Error)
	m1, err := fw.cs.CreateMachineIdentity(ctx, proj.ID, "fam6-o-one", "service", "", "", fw.admin.ID, 0)
	require.NoError(t, err)
	m2, err := fw.cs.CreateMachineIdentity(ctx, proj.ID, "fam6-o-two", "service", "", "", fw.admin.ID, 0)
	require.NoError(t, err)
	pid := suID(proj.ID)

	bind := func(machine uint, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		cat.CreateOIDCBinding(w, suReq(http.MethodPost, body, map[string]string{"id": pid, "machineId": suID(machine)}))
		return w
	}
	t.Run("create: required is 400, duplicate is 409, unknown machine is 404", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, bind(m1.ID, `{"issuer":"","subject":""}`).Code)
		w := bind(m1.ID, `{"issuer":"https://issuer.example","subject":"sub-1"}`)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		assert.Equal(t, http.StatusConflict, bind(m2.ID, `{"issuer":"https://issuer.example","subject":"sub-1"}`).Code, "already bound")
		assert.Equal(t, http.StatusNotFound, bind(9999999, `{"issuer":"https://issuer.example","subject":"sub-2"}`).Code)
	})
	t.Run("delete: a binding of another machine, or none, is 404", func(t *testing.T) {
		var b models.MachineIdentityOIDCBinding
		require.NoError(t, fw.db.Where("machine_identity_id = ?", m1.ID).First(&b).Error)
		del := func(machine uint, binding string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.DeleteOIDCBinding(w, suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": suID(machine), "bindingId": binding}))
			return w
		}
		assert.Equal(t, http.StatusNotFound, del(m2.ID, suID(b.ID)).Code, "the binding belongs to another machine")
		assert.Equal(t, http.StatusNotFound, del(m1.ID, "9999999").Code)
		assert.Equal(t, http.StatusOK, del(m1.ID, suID(b.ID)).Code)
	})
	t.Run("migrate: no username is 400, an unknown user is 404, a read fault is 503", func(t *testing.T) {
		mig := func(body string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.MigrateUserToMachine(w, suReq(http.MethodPost, body, map[string]string{"id": pid}))
			return w
		}
		assert.Equal(t, http.StatusBadRequest, mig(`{"username":""}`).Code)
		assert.Equal(t, http.StatusNotFound, mig(`{"username":"nobody-fam6"}`).Code)
		armFamily6(fw, "GetUserByUsername")
		requireFold503(t, mig(`{"username":"fold-admin"}`), "GetUserByUsername fault")
		fw.faulty.Arm(nil)
	})
	t.Run("transition and token routes: unknown machine is 404, bad action is 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		cat.TransitionMachineIdentity(w, suReq(http.MethodPut, `{"action":"suspend"}`, map[string]string{"id": pid, "machineId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code)
		w = httptest.NewRecorder()
		cat.IssueMachineToken(w, suReq(http.MethodPost, `{}`, map[string]string{"id": pid, "machineId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code)
		w = httptest.NewRecorder()
		cat.ClassifyMachineIdentity(w, suReq(http.MethodPatch, `{"classification":"bogus"}`, map[string]string{"id": pid, "machineId": suID(m1.ID)}))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestErrFamily6_Item4_DynamicSecretRefusalsAreClassifiedBySentinel(t *testing.T) {
	fw := newFoldWorld(t)
	h := NewDynamicSecretHandler(fw.cs)

	// A config whose project is gone: IssueLease refuses with core.ErrDynamicSecretNotFound.
	cfg := &models.DynamicSecretConfig{Name: "fam6-dyn", ProjectID: 9999999, BackendType: "postgres"}
	require.NoError(t, fw.db.Create(cfg).Error)

	w := httptest.NewRecorder()
	h.IssueLease(w, suReq(http.MethodPost, `{}`, map[string]string{"id": suID(cfg.ID)}))
	assert.Equal(t, http.StatusNotFound, w.Code, "a config whose project is gone is a not-found, not a bad gateway: %s", w.Body.String())

	w = httptest.NewRecorder()
	h.ClassifyConfig(w, suReq(http.MethodPatch, `{"classification":"bogus"}`, map[string]string{"id": suID(cfg.ID)}))
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A read fault stays 503.
	fw.faulty.Arm(&faultstorage.FaultSpec{Method: "GetProject", NthCall: 1, Kind: faultstorage.KindError, Err: errFaultNotFoundText})
	w = httptest.NewRecorder()
	h.IssueLease(w, suReq(http.MethodPost, `{}`, map[string]string{"id": suID(cfg.ID)}))
	require.True(t, fw.faulty.Fired())
	requireFold503(t, w, "GetProject fault")
	fw.faulty.Arm(nil)
}

// TestErrFamily6_Item4_OIDCBindingWithoutGlobalAdminIs403 drives POST .../oidc-bindings as
// an actor who is admin of the machine's project but holds no install-wide admin role
// (#127: the (issuer, subject) namespace is global). Core refuses with
// errAdminAuthorityRequired; the route must answer 403 (main gave 400 by text, the
// sentinel migration gave 500) and must write no binding.
func TestErrFamily6_Item4_OIDCBindingWithoutGlobalAdminIs403(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	cat := NewCatalogHandler(fw.cs)

	proj := &models.Project{Name: "fam6-oa-proj"}
	require.NoError(t, fw.db.Create(proj).Error)
	m, err := fw.cs.CreateMachineIdentity(ctx, proj.ID, "fam6-oa-machine", "service", "", "", fw.admin.ID, 0)
	require.NoError(t, err)

	// Move the actor's bypass role from global scope to the machine's project only.
	require.NoError(t, fw.db.Exec("DELETE FROM user_roles").Error)
	var bypass models.Role
	require.NoError(t, fw.db.Where("name = ?", "fold-bypass").First(&bypass).Error)
	require.NoError(t, fw.local.AssignRole(ctx, fw.admin.ID, bypass.ID, corestorage.Scope{ProjectID: proj.ID}))

	w := httptest.NewRecorder()
	cat.CreateOIDCBinding(w, suReq(http.MethodPost, `{"issuer":"https://issuer.example","subject":"victim-sub"}`,
		map[string]string{"id": suID(proj.ID), "machineId": suID(m.ID)}))
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	var n int64
	require.NoError(t, fw.db.Model(&models.MachineIdentityOIDCBinding{}).Count(&n).Error)
	assert.Zero(t, n, "a refused binding must not be written")
}
