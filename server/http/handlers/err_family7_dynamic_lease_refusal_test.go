package handlers

// CORE-ERR-FAMILY-7 item 2: the dynamic-secret lease refusals (disabled config, lease not
// active, expired lease, active-lease limit) were untyped core errors. The handler picked
// their message by matching an allowlist of texts (isSafeDynamicSecretError) and answered
// them with the backend-failure fallback 502, so a caller could not tell "this lease is
// already revoked" from "the target database is down". They match
// core.ErrDynamicSecretPrecondition now and answer 409 with core's text.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestErrFamily7_DynamicLeaseStateRefusalsAre409(t *testing.T) {
	_, _, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}))
	h := NewDynamicSecretHandler(errFamily7DynamicCore(store.NewLocalStorage(db)))

	limited := &models.DynamicSecretConfig{Name: "limited", ProjectID: 1, EnvironmentID: 10, BackendType: "postgres", MaxActiveLeases: 1}
	require.NoError(t, db.Create(limited).Error)
	disabled := &models.DynamicSecretConfig{Name: "disabled", ProjectID: 1, EnvironmentID: 10, BackendType: "postgres", Disabled: true}
	require.NoError(t, db.Create(disabled).Error)
	now := time.Now()
	leases := map[string]*models.DynamicSecretLease{
		"active":  {LeaseID: "ef7-active", Status: "active", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		"revoked": {LeaseID: "ef7-revoked", Status: "revoked", IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		"expired": {LeaseID: "ef7-expired", Status: "active", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	}
	for _, l := range leases {
		l.ConfigID, l.ProjectID, l.EnvironmentID = limited.ID, 1, 10
		require.NoError(t, db.Create(l).Error)
	}

	issue := func(cfgID uint) *httptest.ResponseRecorder {
		id := fmt.Sprint(cfgID)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/"+id+"/issue", nil)
		w := httptest.NewRecorder()
		h.IssueLease(w, withFolderAdminCtx(withChiParam(r, "id", id)))
		return w
	}
	onLease := func(op, leaseID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/"+leaseID+"/"+op, bytes.NewBufferString(`{}`))
		r = withFolderAdminCtx(withChiParam(r, "leaseID", leaseID))
		w := httptest.NewRecorder()
		if op == "revoke" {
			h.RevokeLease(w, r)
		} else {
			h.RenewLease(w, r)
		}
		return w
	}

	cases := []struct {
		name string
		call func() *httptest.ResponseRecorder
		text string
	}{
		{"issue/disabled config", func() *httptest.ResponseRecorder { return issue(disabled.ID) }, "dynamic-secret config is disabled"},
		{"issue/active-lease limit", func() *httptest.ResponseRecorder { return issue(limited.ID) }, "active-lease limit reached"},
		{"revoke/lease not active", func() *httptest.ResponseRecorder { return onLease("revoke", "ef7-revoked") }, "lease is not active"},
		{"renew/lease not active", func() *httptest.ResponseRecorder { return onLease("renew", "ef7-revoked") }, "lease is not active"},
		{"renew/lease expired", func() *httptest.ResponseRecorder { return onLease("renew", "ef7-expired") }, "lease has expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.call()
			require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
			var body struct {
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Contains(t, body.Message, tc.text, "the refusal says what to do, it is not masked")
		})
	}
}

// A backend error whose text happens to contain one of the phrases the old allowlist
// matched is still a backend error: masked, and the route's fallback status. Red while the
// handler classified by text (it passed the driver message through).
func TestErrFamily7_DynamicSecretMessageIsNotClassifiedByText(t *testing.T) {
	err := fmt.Errorf("failed to revoke on target: %w",
		errors.New(`pq: role "v-lease-x" lease not found on host db-prod.internal:5432`))
	msg := dynamicSecretClientMessage(err, "test")
	assert.NotContains(t, msg, "db-prod", "driver text must not reach the client")
	assert.Equal(t, clientSafe(err), msg)
	assert.Equal(t, http.StatusBadGateway, dynamicSecretStatus(err, http.StatusBadGateway))
}
