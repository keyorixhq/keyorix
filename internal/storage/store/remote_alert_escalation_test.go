// remote_alert_escalation_test.go — exercises the RemoteStorage stubs for
// alert escalation. Every method calls remoteUnsupported() immediately, so
// we only need to confirm each returns a non-nil error — no HTTP server needed.
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAlertEscalationRemote(t *testing.T) *store.RemoteStorage {
	t.Helper()
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:1"))
	require.NoError(t, err)
	return rs
}

func TestRemoteAlertEscalation_CreateReturnsUnsupported(t *testing.T) {
	rs := newAlertEscalationRemote(t)
	err := rs.CreateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{})
	assert.ErrorContains(t, err, "CreateAlertEscalationPolicy")
}

func TestRemoteAlertEscalation_GetReturnsUnsupported(t *testing.T) {
	rs := newAlertEscalationRemote(t)
	_, err := rs.GetAlertEscalationPolicy(context.Background(), 1)
	assert.ErrorContains(t, err, "GetAlertEscalationPolicy")
}

func TestRemoteAlertEscalation_ListReturnsUnsupported(t *testing.T) {
	rs := newAlertEscalationRemote(t)
	_, err := rs.ListAlertEscalationPolicies(context.Background())
	assert.ErrorContains(t, err, "ListAlertEscalationPolicies")
}

func TestRemoteAlertEscalation_UpdateReturnsUnsupported(t *testing.T) {
	rs := newAlertEscalationRemote(t)
	err := rs.UpdateAlertEscalationPolicy(context.Background(), &models.AlertEscalationPolicy{})
	assert.ErrorContains(t, err, "UpdateAlertEscalationPolicy")
}

func TestRemoteAlertEscalation_DeleteReturnsUnsupported(t *testing.T) {
	rs := newAlertEscalationRemote(t)
	err := rs.DeleteAlertEscalationPolicy(context.Background(), 1)
	assert.ErrorContains(t, err, "DeleteAlertEscalationPolicy")
}

func TestRemoteAlertEscalation_ListUnacknowledgedReturnsUnsupported(t *testing.T) {
	rs := newAlertEscalationRemote(t)
	_, err := rs.ListUnacknowledgedAnomalyAlertsBefore(context.Background(), time.Now())
	assert.ErrorContains(t, err, "ListUnacknowledgedAnomalyAlertsBefore")
}
