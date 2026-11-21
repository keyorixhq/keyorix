package handlers

// ERRMAP-TAILS-NOV-6 item 1: a SCIM write that fails because the audit log or a storage
// read is down is a retryable 503 (RFC 7644 error body, Retry-After, no scimType), like
// every other REST handler answers these (sendAuditUnavailable, sendStorageUnavailable).
// Before, classifySCIMError had no case for either sentinel, so an IdP got a 500 with
// the generic detail and could not tell "retry shortly" from "broken".

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func assertSCIMOutage503(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := assertSCIMErrorBody(t, w, http.StatusServiceUnavailable)
	assert.Equal(t, strconv.Itoa(middleware.WriteContentionRetryAfterSeconds), w.Header().Get("Retry-After"))
	assert.Nil(t, body["scimType"])
	assert.Equal(t, scimBusyDetail, body["detail"])
}

// TestSCIM_AuditOutage_Is503RetryAfter: the audit row of a provisioning write is
// refused, the transaction rolled back, nothing was created, and a retry is right.
func TestSCIM_AuditOutage_Is503RetryAfter(t *testing.T) {
	auditDown := errors.New("injected: audit log refused the row " + scimInjectedDetail)

	t.Run("create user", func(t *testing.T) {
		h, fs, db := setupSCIMFaultTest(t)
		fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: auditDown})
		w := httptest.NewRecorder()
		h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users",
			bytes.NewReader([]byte(`{"userName":"new@corp.com","externalId":"idp-new"}`))))
		require.True(t, fs.Fired(), "the armed audit fault must have fired")
		fs.Arm(nil)
		assertSCIMOutage503(t, w)
		var n int64
		require.NoError(t, db.Table("users").Where("email = ?", "new@corp.com").Count(&n).Error)
		assert.Zero(t, n, "the refused audit row must roll the account back")
	})

	t.Run("create group", func(t *testing.T) {
		h, fs, _ := setupSCIMFaultTest(t)
		fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: auditDown})
		w := httptest.NewRecorder()
		h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups",
			bytes.NewReader([]byte(`{"displayName":"Engineers"}`))))
		require.True(t, fs.Fired(), "the armed audit fault must have fired")
		fs.Arm(nil)
		assertSCIMOutage503(t, w)
	})
}

// TestSCIM_StorageReadFault_Is503RetryAfter: a failed storage read is a fault, not a
// verdict: the IdP is told to retry, never "not found" and never a bare 500.
func TestSCIM_StorageReadFault_Is503RetryAfter(t *testing.T) {
	h, fs, _ := setupSCIMFaultTest(t)
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups",
		bytes.NewReader([]byte(`{"displayName":"Engineers"}`))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, gid)

	fs.Arm(&faultstorage.FaultSpec{Method: "GetGroup", NthCall: 1, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
	w = scimDo(h.GetGroup, http.MethodGet, gid, "")
	require.True(t, fs.Fired(), "the armed read fault must have fired")
	fs.Arm(nil)
	assertSCIMOutage503(t, w)
}
