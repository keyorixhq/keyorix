package handlers

// storage_unavailable_test.go — STORAGE-ERR-CLASS-1 item 5 (REST).
//
// A storage READ fault inside a revoke / suspend / unbind / withdraw / attest used
// to be folded into "<thing> not found" by core and answered 404. Core now returns
// core.ErrStorageReadUnavailable and every handler below answers it exactly like an
// audit-log outage (sendAuditUnavailable): 503, Retry-After, code
// "storage_unavailable". A true not-found stays 404 on the same routes.

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
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func suReq(method, body string, params map[string]string) *http.Request {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	return withUserCtx(withChiParams(r, params))
}

func suID(id uint) string { return strconv.FormatUint(uint64(id), 10) }

type suErrBody struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func TestStorageUnavailable_RESTMapping(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxstorageunavail_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	cs := core.NewKeyorixCore(faulty)
	cat := NewCatalogHandler(cs)
	dyn := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "su-proj"}
	require.NoError(t, db.Create(proj).Error)
	pid := suID(proj.ID)
	machine := &models.MachineIdentity{ProjectID: proj.ID, Name: "su-m", IdentityType: "other", State: "active"}
	require.NoError(t, db.Create(machine).Error)
	mid := suID(machine.ID)
	cred := &models.MachineIdentityCredential{MachineIdentityID: machine.ID, Name: "c", TokenHash: "h1", TokenPrefix: "kx_m"}
	require.NoError(t, db.Create(cred).Error)
	binding := &models.MachineIdentityOIDCBinding{MachineIdentityID: machine.ID}
	require.NoError(t, db.Create(binding).Error)
	inv := &models.ProjectInvitation{ProjectID: proj.ID, Email: "su@example.com", Role: "viewer", State: core.InvitationPending, CreatedAt: time.Now()}
	require.NoError(t, db.Create(inv).Error)
	membership := &models.ProjectMembership{ProjectID: proj.ID, UserID: 77, Role: "viewer", State: core.MembershipInvited, InvitedAt: time.Now()}
	require.NoError(t, db.Create(membership).Error)
	areq := &models.AccessRequest{ProjectID: proj.ID, UserID: 1, SuggestedRole: "viewer", State: core.AccessRequestPending, CreatedAt: time.Now()}
	require.NoError(t, db.Create(areq).Error)
	lease := &models.DynamicSecretLease{LeaseID: "su-lease", ConfigID: 1, Status: "active"}
	require.NoError(t, db.Create(lease).Error)

	cases := []struct {
		name   string
		fault  string
		handle func(http.ResponseWriter, *http.Request)
		req    func() *http.Request
	}{
		{"list OIDC bindings", "GetMachineIdentity", cat.ListOIDCBindings, func() *http.Request {
			return suReq(http.MethodGet, "", map[string]string{"id": pid, "machineId": mid})
		}},
		{"delete OIDC binding", "GetOIDCBindingByID", cat.DeleteOIDCBinding, func() *http.Request {
			return suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": mid, "bindingId": suID(binding.ID)})
		}},
		{"revoke machine token", "GetMachineIdentityCredentialByID", cat.RevokeMachineToken, func() *http.Request {
			return suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": mid, "tokenId": suID(cred.ID)})
		}},
		{"revoke machine identity", "LockMachineIdentityForUpdate", cat.TransitionMachineIdentity, func() *http.Request {
			return suReq(http.MethodPost, `{"action":"revoke"}`, map[string]string{"id": pid, "machineId": mid})
		}},
		{"revoke membership", "GetProjectMembership", cat.TransitionMembership, func() *http.Request {
			return suReq(http.MethodPut, `{"action":"revoke"}`, map[string]string{"id": pid, "membershipId": suID(membership.ID)})
		}},
		{"revoke invitation", "GetProjectInvitation", cat.RevokeInvitation, func() *http.Request {
			return suReq(http.MethodDelete, "", map[string]string{"id": pid, "invitationId": suID(inv.ID)})
		}},
		{"withdraw access request", "GetAccessRequest", cat.WithdrawAccessRequest, func() *http.Request {
			return suReq(http.MethodPost, "", map[string]string{"id": pid, "requestId": suID(areq.ID)})
		}},
		{"revoke dynamic lease (lookup)", "GetDynamicSecretLease", dyn.RevokeLease, func() *http.Request {
			return suReq(http.MethodDelete, "", map[string]string{"leaseID": lease.LeaseID})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			w := httptest.NewRecorder()
			tc.handle(w, tc.req())
			require.True(t, faulty.Fired(), "the read fault must be reached")
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "a storage read fault is 503, not 404/500: %s", w.Body.String())
			assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
			var body suErrBody
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, storageUnavailableCode, body.Error)
			assert.Equal(t, core.StorageReadUnavailableMessage, body.Message)
			assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "the driver cause must not reach the client")
			faulty.Arm(nil)
		})
	}

	t.Run("a true not-found is still 404 on the same routes", func(t *testing.T) {
		w := httptest.NewRecorder()
		cat.ListOIDCBindings(w, suReq(http.MethodGet, "", map[string]string{"id": pid, "machineId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, w.Header().Get("Retry-After"))

		w = httptest.NewRecorder()
		cat.RevokeInvitation(w, suReq(http.MethodDelete, "", map[string]string{"id": pid, "invitationId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code)

		w = httptest.NewRecorder()
		cat.RevokeMachineToken(w, suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": mid, "tokenId": "9999999"}))
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("the retried revoke succeeds after the fault clears", func(t *testing.T) {
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetMachineIdentityCredentialByID", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
		w := httptest.NewRecorder()
		cat.RevokeMachineToken(w, suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": mid, "tokenId": suID(cred.ID)}))
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		var row models.MachineIdentityCredential
		require.NoError(t, db.First(&row, cred.ID).Error)
		assert.False(t, row.Revoked, "the 503 means the revoke was not applied")

		w = httptest.NewRecorder()
		cat.RevokeMachineToken(w, suReq(http.MethodDelete, "", map[string]string{"id": pid, "machineId": mid, "tokenId": suID(cred.ID)}))
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NoError(t, db.First(&row, cred.ID).Error)
		assert.True(t, row.Revoked)
	})
}
