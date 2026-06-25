package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func riskCore(store *MockStorage, now time.Time) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return now }}
}

func TestCreateRiskException_ValidatesAndAudits(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("CreateRiskException", mock.Anything, mock.MatchedBy(func(e *models.RiskException) bool {
		return e.Title == "accept SoD for migration" && e.Category == "sod" && e.CreatedBy == 9
	})).Return(&models.RiskException{ID: 1, Title: "accept SoD for migration"}, nil)
	var audited string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventRiskExceptionCreated {
			audited = ev.EventType
			return true
		}
		return false
	})).Return(nil)

	c := riskCore(store, now)
	_, err := c.CreateRiskException(context.Background(), 9, "accept SoD for migration", "sod", "alice+roles.assign/secrets.delete", "temporary during cutover", now.AddDate(0, 0, 30))
	require.NoError(t, err)
	assert.Equal(t, EventRiskExceptionCreated, audited)
}

func TestCreateRiskException_Rejects(t *testing.T) {
	now := time.Now()
	c := riskCore(new(MockStorage), now)

	_, err := c.CreateRiskException(context.Background(), 1, "", "sod", "", "", now.Add(time.Hour))
	require.Error(t, err, "title + justification required")

	_, err = c.CreateRiskException(context.Background(), 1, "t", "bogus", "", "j", now.Add(time.Hour))
	require.Error(t, err, "invalid category")

	_, err = c.CreateRiskException(context.Background(), 1, "t", "sod", "", "j", now.Add(-time.Hour))
	require.Error(t, err, "expiry must be in the future")

	// Must sunset: an expiry beyond the max duration is refused (no effectively-forever
	// waiver).
	_, err = c.CreateRiskException(context.Background(), 1, "t", "sod", "", "j", now.AddDate(5, 0, 0))
	require.Error(t, err, "expiry beyond the cap is rejected")
	require.Contains(t, err.Error(), "must be within")
}

func TestListRiskExceptions_ComputesStatusAndFilters(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	rows := []*models.RiskException{
		{ID: 1, Title: "active", ExpiresAt: now.AddDate(0, 0, 10)},  // active
		{ID: 2, Title: "expired", ExpiresAt: now.AddDate(0, 0, -1)}, // expired
	}
	store.On("ListRiskExceptions", mock.Anything, true).Return(rows, nil)

	c := riskCore(store, now)

	// activeOnly drops the expired one.
	active, err := c.ListRiskExceptions(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.Equal(t, ExceptionStatusActive, active[0].Status)
	assert.Equal(t, "active", active[0].Title)
}

func TestRevokeRiskException(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x"}, nil)
	store.On("UpdateRiskException", mock.Anything, mock.MatchedBy(func(e *models.RiskException) bool {
		return e.ID == 5 && e.Revoked && e.RevokedBy == 3 && e.RevokedAt != nil
	})).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := riskCore(store, now)
	require.NoError(t, c.RevokeRiskException(context.Background(), 3, 5))
}

func TestCountActiveRiskExceptions(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("ListRiskExceptions", mock.Anything, true).Return([]*models.RiskException{
		{ID: 1, ExpiresAt: now.AddDate(0, 0, 3)},  // active, expiring soon (<14d)
		{ID: 2, ExpiresAt: now.AddDate(0, 0, 60)}, // active, not soon
		{ID: 3, ExpiresAt: now.AddDate(0, 0, -1)}, // expired
	}, nil)

	c := riskCore(store, now)
	active, soon, err := c.CountActiveRiskExceptions(context.Background(), riskExpiringSoonWindow)
	require.NoError(t, err)
	assert.Equal(t, 2, active)
	assert.Equal(t, 1, soon)
}
