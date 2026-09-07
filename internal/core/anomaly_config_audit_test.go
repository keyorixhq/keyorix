// anomaly_config_audit_test.go — regression coverage for the anomaly-config
// audit-trail gap: UpdateAnomalyConfig stores UpdatedBy/UpdatedAt on the
// singleton row (ID=1) but used to call no writeAuditEvent at all. An admin
// could disable ML/off-hours detection deployment-wide, act while detection
// was off, then restore the defaults -- the row would show only the final
// restored state, with no audit-trail history of the intervening window.
//
// This is distinct from ApplyAnomalyConfig's existing
// EventAnomalyBusinessHoursConfigured audit (anomaly.go/anomaly_config_test.go),
// which only fires for the off-hours band as applied to the live detector
// (change-deduped across scheduler ticks) and never covers ML enable/disable,
// lookback, or quarantine. The tests here cover the raw admin PUT itself.
//
// Verified RED before the fix: reverting the writeConfigChangeAuditEvent call
// in UpdateAnomalyConfig makes TestUpdateAnomalyConfig_AuditsMLDisable below
// fail with 0 calls to LogAuditEvent (confirmed manually during development
// of this fix -- see config_change_audit_guard_test.go for the permanent
// structural guard).
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestUpdateAnomalyConfig_AuditsMLDisable is the core threat-model test: an
// admin flips ml_enabled from true to false (disabling detection), which must
// be on the permanent audit record with both the before and after state.
func TestUpdateAnomalyConfig_AuditsMLDisable(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	prior := &models.AnomalyConfigRecord{MLEnabled: true, MLThreshold: 0.6, OffHoursEnabled: true}
	store.On("GetAnomalyConfig", ctx).Return(prior, nil)
	store.On("SaveAnomalyConfig", ctx, mock.AnythingOfType("*models.AnomalyConfigRecord")).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	const actorID = uint(9101)
	next := &models.AnomalyConfigRecord{MLEnabled: false, MLThreshold: 0.6, OffHoursEnabled: true}
	err := c.UpdateAnomalyConfig(ctx, next, "admin", actorID)
	require.NoError(t, err)

	require.NotNil(t, captured, "disabling anomaly detection must write an audit event")
	assert.Equal(t, EventAnomalyConfigUpdated, captured.EventType)
	require.NotNil(t, captured.UserID, "the acting admin must be attributed by numeric ID")
	assert.Equal(t, actorID, *captured.UserID)
	assert.Contains(t, captured.Diff, `"ml_enabled":true`, "the diff must carry the PRIOR (before) ml_enabled state")
	assert.Contains(t, captured.Diff, `"ml_enabled":false`, "the diff must carry the NEW (after) ml_enabled state")
	assert.Contains(t, captured.Description, "ml_enabled=false")
}

// TestUpdateAnomalyConfig_AuditsOffHoursDisable covers the other detection
// knob named explicitly in the finding: off_hours_enabled.
func TestUpdateAnomalyConfig_AuditsOffHoursDisable(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	prior := &models.AnomalyConfigRecord{OffHoursEnabled: true, OffHoursStart: 22, OffHoursEnd: 6}
	store.On("GetAnomalyConfig", ctx).Return(prior, nil)
	store.On("SaveAnomalyConfig", ctx, mock.AnythingOfType("*models.AnomalyConfigRecord")).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	next := &models.AnomalyConfigRecord{OffHoursEnabled: false}
	err := c.UpdateAnomalyConfig(ctx, next, "admin", 9102)
	require.NoError(t, err)

	require.NotNil(t, captured)
	assert.Contains(t, captured.Diff, `"off_hours_enabled":true`)
	assert.Contains(t, captured.Diff, `"off_hours_enabled":false`)
}

// TestUpdateAnomalyConfig_BeforeFetchFailureStillAuditsWrite confirms the
// best-effort "before" fetch: if reading the PRIOR config fails, the write
// (and its audit event) must still happen -- a missing before-snapshot must
// never suppress the record that the change occurred.
func TestUpdateAnomalyConfig_BeforeFetchFailureStillAuditsWrite(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	store.On("GetAnomalyConfig", ctx).Return(nil, errors.New("db unavailable"))
	store.On("SaveAnomalyConfig", ctx, mock.AnythingOfType("*models.AnomalyConfigRecord")).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	cfg := &models.AnomalyConfigRecord{MLEnabled: true}
	err := c.UpdateAnomalyConfig(ctx, cfg, "admin", 9103)
	require.NoError(t, err)
	require.NotNil(t, captured, "a failed before-fetch must not suppress the audit write")
	assert.Contains(t, captured.Diff, `"ml_enabled":true`)
}
