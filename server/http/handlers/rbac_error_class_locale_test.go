// rbac_error_class_locale_test.go — the RBAC routes must answer from the KIND of
// failure, not from the language of its message (ERRLOSS-SENTINELS-1 task 3.2,
// same class as #2461/#2905): not-found -> 404, refusal -> 403, duplicate ->
// 409, storage failure -> 5xx, under the shipped English text and under a
// translated locale.
//
// These handlers used to classify core's error with strings.Contains on
// "not found", "already assigned", "built-in", "do not hold it yourself" and
// friends. Under a translated locale the i18n part of those texts no longer
// matches, so a real 404 became a 500. Like the other locale tests these flip
// the process-global localizer and are deliberately NOT t.Parallel().
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	rbacMissing = "99999"
	// rbacAdminID is the global admin withUserCtx / openTestDB wire up; rbacPlainID
	// holds no role anywhere.
	rbacAdminID uint = 1
	rbacPlainID uint = 2
)

// rbacIDs are the ids a route is driven with: real ones for a fault/duplicate
// case, rbacMissing for a not-found case.
type rbacIDs struct{ role, perm, group, user string }

func rbacRealIDs(t *testing.T, db *gorm.DB) rbacIDs {
	t.Helper()
	role := mustCreateRole(t, db, "fx-role")
	perm := mustCreatePermission(t, db, "fx.perm", "fx", "perm")
	group := mustCreateGroup(t, db, "fx-group")
	return rbacIDs{
		role:  strconv.FormatUint(uint64(role.ID), 10),
		perm:  strconv.FormatUint(uint64(perm.ID), 10),
		group: strconv.FormatUint(uint64(group.ID), 10),
		user:  strconv.FormatUint(uint64(rbacPlainID), 10),
	}
}

func rbacBuiltinRoleID(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var r models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&r).Error)
	return strconv.FormatUint(uint64(r.ID), 10)
}

func rbacDo(fn http.HandlerFunc, method, target, body string, params map[string]string, actor uint) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req = withUserCtxID(req, actor, "actor")
	if params != nil {
		req = withChiParams(req, params)
	}
	w := httptest.NewRecorder()
	fn(w, req)
	return w
}

type rbacRoute struct {
	name string
	// fault is the storage method whose failure this route must surface as 5xx
	// ("" = the route has no distinct lookup to fail).
	fault string
	call  func(h *RBACHandler, ids rbacIDs) *httptest.ResponseRecorder
}

func rbacLookupRoutes() []rbacRoute {
	return []rbacRoute{
		{"GetRole", "GetRole", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.GetRole, http.MethodGet, "/roles/"+i.role, "", map[string]string{"id": i.role}, rbacAdminID)
		}},
		{"GetRoleByName", "GetRoleByName", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			name := "nobody"
			if i.role != rbacMissing {
				name = "fx-role"
			}
			return rbacDo(h.GetRoleByName, http.MethodGet, "/roles/by-name?name="+name, "", nil, rbacAdminID)
		}},
		{"UpdateRole", "GetRole", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.UpdateRole, http.MethodPut, "/roles/"+i.role, `{"description":"x"}`, map[string]string{"id": i.role}, rbacAdminID)
		}},
		{"DeleteRole", "GetRole", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.DeleteRole, http.MethodDelete, "/roles/"+i.role, "", map[string]string{"id": i.role}, rbacAdminID)
		}},
		{"GetRolePermissions", "GetRole", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.GetRolePermissions, http.MethodGet, "/roles/"+i.role+"/permissions", "", map[string]string{"id": i.role}, rbacAdminID)
		}},
		{"GetPermission", "GetPermission", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.GetPermission, http.MethodGet, "/permissions/"+i.perm, "", map[string]string{"id": i.perm}, rbacAdminID)
		}},
		{"AssignPermissionToRole", "GetRole", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.AssignPermissionToRole, http.MethodPost, "/roles/"+i.role+"/permissions",
				fmt.Sprintf(`{"permission_id":%s}`, i.perm), map[string]string{"id": i.role}, rbacAdminID)
		}},
		{"RemovePermissionFromRole", "GetRole", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.RemovePermissionFromRole, http.MethodDelete, "/roles/"+i.role+"/permissions/"+i.perm, "",
				map[string]string{"id": i.role, "permissionId": i.perm}, rbacAdminID)
		}},
		{"GetUserRoles", "GetUser", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.GetUserRoles, http.MethodGet, "/user-roles/user/"+i.user, "", map[string]string{"userId": i.user}, rbacAdminID)
		}},
		{"AssignRoleToGroup", "GetGroup", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.AssignRoleToGroup, http.MethodPost, "/groups/"+i.group+"/roles",
				fmt.Sprintf(`{"role_id":%s}`, realOr(i.role, "1")), map[string]string{"id": i.group}, rbacAdminID)
		}},
		{"RemoveRoleFromGroup", "GetGroup", func(h *RBACHandler, i rbacIDs) *httptest.ResponseRecorder {
			return rbacDo(h.RemoveRoleFromGroup, http.MethodDelete, "/groups/"+i.group+"/roles/"+i.role, "",
				map[string]string{"id": i.group, "roleId": i.role}, rbacAdminID)
		}},
	}
}

func rbacRouteNamed(name string) rbacRoute {
	for _, rt := range rbacLookupRoutes() {
		if rt.name == name {
			return rt
		}
	}
	panic("no RBAC route named " + name)
}

func realOr(v, fallback string) string {
	if v == rbacMissing {
		return fallback
	}
	return v
}

// Every lookup route answers 404 for a missing target in both locales.
func TestRBACRoutes_MissingTargetIs404InEveryLocale(t *testing.T) {
	missing := rbacIDs{role: rbacMissing, perm: rbacMissing, group: rbacMissing, user: rbacMissing}
	for _, lang := range errorClassLocales {
		for _, rt := range rbacLookupRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, _ := setupRBACTestWithDB(t)
				withErrorTextLocale(t, lang)
				w := rt.call(h, missing)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// Targets that exist on every id but one: the missing permission of
// AssignPermissionToRole and the role not held by the user/group are 404 too.
func TestRBACRoutes_MissingSecondaryTargetIs404InEveryLocale(t *testing.T) {
	cases := []struct {
		name string
		call func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder
	}{
		{"AssignPermissionToRole/permission missing", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			ids.perm = rbacMissing
			return rbacRouteNamed("AssignPermissionToRole").call(h, ids)
		}},
		{"RemovePermissionFromRole/permission not bundled", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			return rbacRouteNamed("RemovePermissionFromRole").call(h, rbacRealIDs(t, db))
		}},
		{"RemoveRole/role not assigned", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			return rbacDo(h.RemoveRole, http.MethodDelete, "/user-roles", fmt.Sprintf(`{"user_id":%s,"role_id":%s}`, ids.user, ids.role), nil, rbacAdminID)
		}},
		{"RemoveRoleFromGroup/role not assigned", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			return rbacRouteNamed("RemoveRoleFromGroup").call(h, rbacRealIDs(t, db))
		}},
	}
	for _, lang := range errorClassLocales {
		for _, c := range cases {
			t.Run(lang+"/"+c.name, func(t *testing.T) {
				h, _, db := setupRBACTestWithDB(t)
				withErrorTextLocale(t, lang)
				w := c.call(t, h, db)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A refusal is 403 in every locale: a built-in role cannot be updated or
// deleted, and an actor cannot bundle a permission they do not hold.
func TestRBACRoutes_RefusalIs403InEveryLocale(t *testing.T) {
	cases := []struct {
		name string
		call func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder
	}{
		{"UpdateRole/built-in", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			id := rbacBuiltinRoleID(t, db)
			return rbacDo(h.UpdateRole, http.MethodPut, "/roles/"+id, `{"description":"x"}`, map[string]string{"id": id}, rbacAdminID)
		}},
		{"DeleteRole/built-in", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			id := rbacBuiltinRoleID(t, db)
			return rbacDo(h.DeleteRole, http.MethodDelete, "/roles/"+id, "", map[string]string{"id": id}, rbacAdminID)
		}},
		{"AssignPermissionToRole/actor does not hold it", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			return rbacDo(h.AssignPermissionToRole, http.MethodPost, "/roles/"+ids.role+"/permissions",
				fmt.Sprintf(`{"permission_id":%s}`, ids.perm), map[string]string{"id": ids.role}, rbacPlainID)
		}},
		{"UpdateRole/bundling a permission the actor does not hold", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			return rbacDo(h.UpdateRole, http.MethodPut, "/roles/"+ids.role, `{"permissions":["fx.perm"]}`, map[string]string{"id": ids.role}, rbacPlainID)
		}},
	}
	for _, lang := range errorClassLocales {
		for _, c := range cases {
			t.Run(lang+"/"+c.name, func(t *testing.T) {
				h, _, db := setupRBACTestWithDB(t)
				withErrorTextLocale(t, lang)
				w := c.call(t, h, db)
				assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A duplicate grant, a duplicate permission bundle and a reserved role name are
// 409 in every locale.
func TestRBACRoutes_DuplicateIs409InEveryLocale(t *testing.T) {
	cases := []struct {
		name string
		call func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder
	}{
		{"AssignRole/already assigned", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			body := fmt.Sprintf(`{"user_id":%s,"role_id":%s}`, ids.user, ids.role)
			first := rbacDo(h.AssignRole, http.MethodPost, "/user-roles", body, nil, rbacAdminID)
			require.Equal(t, http.StatusCreated, first.Code, "first grant: %s", first.Body.String())
			return rbacDo(h.AssignRole, http.MethodPost, "/user-roles", body, nil, rbacAdminID)
		}},
		{"AssignPermissionToRole/already has permission", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			first := rbacRouteNamed("AssignPermissionToRole").call(h, ids)
			require.Equal(t, http.StatusCreated, first.Code, "first bundle: %s", first.Body.String())
			return rbacRouteNamed("AssignPermissionToRole").call(h, ids)
		}},
		{"AssignRoleToGroup/already assigned", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			ids := rbacRealIDs(t, db)
			first := rbacRouteNamed("AssignRoleToGroup").call(h, ids)
			require.Equal(t, http.StatusCreated, first.Code, "first grant: %s", first.Body.String())
			return rbacRouteNamed("AssignRoleToGroup").call(h, ids)
		}},
		{"CreateRole/reserved name", func(t *testing.T, h *RBACHandler, db *gorm.DB) *httptest.ResponseRecorder {
			return rbacDo(h.CreateRole, http.MethodPost, "/roles",
				`{"name":"system_admin","description":"x","permissions":["fx.perm"]}`, nil, rbacAdminID)
		}},
	}
	for _, lang := range errorClassLocales {
		for _, c := range cases {
			t.Run(lang+"/"+c.name, func(t *testing.T) {
				h, _, db := setupRBACTestWithDB(t)
				withErrorTextLocale(t, lang)
				w := c.call(t, h, db)
				assert.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure on the lookup is a 5xx in every locale: never a 404 that an
// admin would read as "no such role", and never the raw driver text. AssignRoleToGroup,
// RemoveRoleFromGroup and AssignPermissionToRole's permission lookup used to
// embed the not-found text around the driver error, so even English answered 404.
func TestRBACRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	type faultCase struct {
		name   string
		method string
		call   func(h *RBACHandler, ids rbacIDs) *httptest.ResponseRecorder
	}
	var cases []faultCase
	for _, rt := range rbacLookupRoutes() {
		cases = append(cases, faultCase{rt.name, rt.fault, rt.call})
	}
	// The permission lookup of AssignPermissionToRole is a second, distinct call.
	cases = append(cases, faultCase{"AssignPermissionToRole/permission lookup", "GetPermission", rbacRouteNamed("AssignPermissionToRole").call})

	for _, lang := range errorClassLocales {
		for _, c := range cases {
			t.Run(lang+"/"+c.name, func(t *testing.T) {
				_, _, db := setupRBACTestWithDB(t)
				withErrorTextLocale(t, lang)
				ids := rbacRealIDs(t, db)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: c.method, NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("injected: " + c.method),
				})
				fh := NewRBACHandler(core.NewKeyorixCore(faulty))

				w := c.call(fh, ids)
				require.True(t, faulty.Fired(), "%s must reach storage method %s", c.name, c.method)
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			})
		}
	}
}
