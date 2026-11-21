// openapi_declared_statuses_test.go — pins the response statuses openapi.yaml
// declares for operations whose handlers answer a status the spec once left out.
//
// contracttest.AssertOpenAPIResponse validates a body against the declared
// schema but does not fail on a status the operation never declared, so these
// checks read the declared statuses straight from the spec. FuzzOpenAPIStateful
// (server/http) is the oracle that finds such gaps; each case here is the
// deterministic twin of one of its findings.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// declaredStatuses returns the response status keys openapi.yaml declares for one operation.
func declaredStatuses(t *testing.T, method, path string) map[string]bool {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("openapi.yaml")
	require.NoError(t, err)
	item := doc.Paths.Find(path)
	require.NotNil(t, item, "openapi.yaml has no path %s", path)
	op := item.GetOperation(method)
	require.NotNil(t, op, "openapi.yaml has no %s %s", method, path)
	out := map[string]bool{}
	for k := range op.Responses.Map() {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// #4244: the handler answers 204 (no body); the spec declared only 200.
func TestOpenAPIDeclaredStatuses_DeleteRejectionReasonTemplate(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	cw := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"name":"decl","reason":"declared"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	answered := map[int]*httptest.ResponseRecorder{}
	for _, id := range []string{"1", "999", "abc"} {
		w := httptest.NewRecorder()
		h.DeleteRejectionReasonTemplate(w, withChiParam(withUserCtx(
			httptest.NewRequest(http.MethodDelete, "/", nil)), "id", id))
		answered[w.Code] = w
	}
	require.Contains(t, answered, http.StatusNoContent)
	require.Contains(t, answered, http.StatusNotFound)
	require.Contains(t, answered, http.StatusBadRequest)
	assert.Empty(t, answered[http.StatusNoContent].Body.String(), "204 carries no body")

	declared := declaredStatuses(t, http.MethodDelete, "/api/v1/rejection-reason-templates/{id}")
	for code := range answered {
		assert.True(t, declared[strconv.Itoa(code)], "handler answers %d but the spec declares only %v", code, sortedKeys(declared))
	}
	assert.False(t, declared["200"], "the handler never answers 200; a client waiting for it would misread the 204")
}

// VALIDATION-TYPED-NOV-1 leftover: deleteUser and restoreUser refuse a bad id,
// the caller's own account (delete) and user id 0 with 400; the spec left the 400 out.
func TestOpenAPIDeclaredStatuses_DeleteAndRestoreUserRefusals(t *testing.T) {
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)

	call := func(handler http.HandlerFunc, method, id string) *httptest.ResponseRecorder {
		r := withUserCtxS7(withChiParamS7(httptest.NewRequest(method, "/", nil), "id", id))
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	const callerID = "1" // withUserCtxS7 acts as user 1

	cases := []struct {
		name, path, method string
		handler            http.HandlerFunc
		id                 string
	}{
		{"delete non-numeric id", "/api/v1/users/{id}", http.MethodDelete, h.DeleteUser, "abc"},
		{"delete own account", "/api/v1/users/{id}", http.MethodDelete, h.DeleteUser, callerID},
		{"delete user id 0", "/api/v1/users/{id}", http.MethodDelete, h.DeleteUser, "0"},
		{"restore non-numeric id", "/api/v1/users/{id}/restore", http.MethodPost, h.RestoreUser, "abc"},
		{"restore user id 0", "/api/v1/users/{id}/restore", http.MethodPost, h.RestoreUser, "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := call(c.handler, c.method, c.id)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			declared := declaredStatuses(t, c.method, c.path)
			assert.True(t, declared["400"], "handler answers 400 but the spec declares only %v", sortedKeys(declared))
		})
	}
}

// ERRMAP-TAILS-NOV-6 item 2: assignUserRole answers 404 (absent target user) and 503 (read
// fault) since ERRMAP-TAILS-NOV-4, classifySecret, getSecretByName and setSecretAutoRotate
// answer 503 for a secret read fault; the spec left those statuses out. Each case drives
// the real handler to the status (the same fault setups as assign_role_absent_user_test.go
// and secrets_classify_rotate_byname_fault_test.go) and asserts the spec declares it.
func TestOpenAPIDeclaredStatuses_AssignRoleAndSecretReadFaults(t *testing.T) {
	assertDeclared := func(t *testing.T, method, path string, answered map[int]bool) {
		t.Helper()
		declared := declaredStatuses(t, method, path)
		for code := range answered {
			assert.True(t, declared[strconv.Itoa(code)], "%s %s answers %d but the spec declares only %v", method, path, code, sortedKeys(declared))
		}
	}

	t.Run("assignUserRole", func(t *testing.T) {
		_, db := freshCoreS12WithAdmin(t)
		faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
		h := NewRBACHandler(core.NewKeyorixCore(faulty))
		role := &models.Role{Name: "declared-status-role", Description: "d", AssignableScope: models.RoleAssignableAny}
		require.NoError(t, db.Create(role).Error)
		existing := &models.User{Username: "declared-status-user", Email: "declared-status-user@example.test", AccountState: "active"}
		require.NoError(t, db.Create(existing).Error)
		assign := func(target uint) *httptest.ResponseRecorder {
			body, err := json.Marshal(map[string]any{"user_id": target, "role_id": role.ID})
			require.NoError(t, err)
			req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewReader(body)), secretsAdminID, "actor")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.AssignRole(w, req)
			return w
		}
		answered := map[int]bool{}
		w := assign(999999)
		require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		answered[w.Code] = true
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
		w = assign(existing.ID)
		require.True(t, faulty.Fired(), "the GetUser read fault must be reached")
		faulty.Arm(nil)
		require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
		answered[w.Code] = true
		w = assign(existing.ID)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		answered[w.Code] = true
		assertDeclared(t, http.MethodPost, "/api/v1/user-roles", answered)
	})

	t.Run("secret reads", func(t *testing.T) {
		_, db, fx := newSecretsHandlerWithDB(t, "en")
		faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
		h, err := NewSecretHandler(core.NewKeyorixCore(faulty))
		require.NoError(t, err)
		byName := func(name string) *httptest.ResponseRecorder {
			target := fmt.Sprintf("/?name=%s&project_id=%d&environment_id=%d", name, fx.projectID, fx.envID)
			w := httptest.NewRecorder()
			h.GetSecretByName(w, withUserCtxID(httptest.NewRequest(http.MethodGet, target, nil), secretsAdminID, "actor"))
			return w
		}
		cases := []struct {
			method, path, fault string
			call                func(missing bool) *httptest.ResponseRecorder
		}{
			{http.MethodPatch, "/api/v1/secrets/{id}/classification", "GetSecret", func(missing bool) *httptest.ResponseRecorder {
				id := fx.id()
				if missing {
					id = secretsMissingID
				}
				return secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, id, secretsAdminID)
			}},
			{http.MethodPatch, "/api/v1/secrets/{id}/auto-rotate", "GetSecret", func(missing bool) *httptest.ResponseRecorder {
				id := fx.id()
				if missing {
					id = secretsMissingID
				}
				return secretsDo(h.SetAutoRotate, http.MethodPatch, `{"enabled":false}`, id, secretsAdminID)
			}},
			{http.MethodGet, "/api/v1/secrets/by-name", "GetSecretByName", func(missing bool) *httptest.ResponseRecorder {
				if missing {
					return byName("no-such-secret")
				}
				return byName("ec-secret")
			}},
		}
		for _, tc := range cases {
			t.Run(tc.path, func(t *testing.T) {
				answered := map[int]bool{}
				w := tc.call(true)
				require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
				answered[w.Code] = true
				faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
				w = tc.call(false)
				require.True(t, faulty.Fired(), "the %s read fault must be reached", tc.fault)
				faulty.Arm(nil)
				require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
				answered[w.Code] = true
				assertDeclared(t, tc.method, tc.path, answered)
			})
		}
	})
}
