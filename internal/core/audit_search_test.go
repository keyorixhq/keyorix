// audit_search_test.go — unit tests for SearchAuditLogs.
// Uses MockStorage so every branch in audit_search.go is driven directly.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockAuditEvent creates a minimal AuditEvent for seeding.
func mockAuditEvent(id uint, eventType string) *models.AuditEvent {
	tru := true
	uid := uint(1)
	return &models.AuditEvent{
		ID:        id,
		EventType: eventType,
		UserID:    &uid,
		Success:   &tru,
		EventTime: time.Now(),
	}
}

// setupSearchCore returns a core backed by a fresh MockStorage.
func setupSearchCore(t *testing.T) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	return c, ms
}

// ── no filter: returns all events ─────────────────────────────────────────────

func TestSearchAuditLogs_NoFilter(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{
		mockAuditEvent(1, "secret.read"),
		mockAuditEvent(2, "user.login"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.ActorUsername == nil && f.UserID == nil && f.ProjectID == nil
	})).Return(events, int64(2), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Len(t, result.Events, 2)
}

// ── filter by actor username ───────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByActorUsername(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(1, "secret.read")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.ActorUsername != nil && *f.ActorUsername == "alice"
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{ActorUsername: "alice"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by project_id ───────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByProjectID(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(5, "secret.created")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.ProjectID != nil && *f.ProjectID == uint(3)
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{ProjectID: 3})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by action ──────────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByAction(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(2, "user.login")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.Action != nil && *f.Action == "user.login"
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Action: "user.login"})
	require.NoError(t, err)
	assert.Len(t, result.Events, 1)
	assert.Equal(t, "user.login", result.Events[0].EventType)
}

// ── filter by success = true ──────────────────────────────────────────────────

func TestSearchAuditLogs_FilterBySuccessTrue(t *testing.T) {
	c, ms := setupSearchCore(t)
	tru := true
	events := []*models.AuditEvent{mockAuditEvent(3, "secret.read")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.Success != nil && *f.Success
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Success: &tru})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by success = false ─────────────────────────────────────────────────

func TestSearchAuditLogs_FilterBySuccessFalse(t *testing.T) {
	c, ms := setupSearchCore(t)
	fal := false
	fse := true
	ev := &models.AuditEvent{ID: 10, EventType: "user.login", Success: &fse}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.Success != nil && !*f.Success
	})).Return([]*models.AuditEvent{ev}, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Success: &fal})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by time range ──────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByTimeRange(t *testing.T) {
	c, ms := setupSearchCore(t)
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()
	events := []*models.AuditEvent{mockAuditEvent(7, "secret.deleted")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.StartTime != nil && f.EndTime != nil
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Since: since, Until: until})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by IP address ──────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByIPAddress(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(4, "secret.read")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.IPAddress != nil && *f.IPAddress == "10.0.0.1"
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{IPAddress: "10.0.0.1"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by resource_type ────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByResourceType(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{
		mockAuditEvent(1, "secret.read"),
		mockAuditEvent(2, "secret.created"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.ResourceType != nil && *f.ResourceType == "secret"
	})).Return(events, int64(2), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{ResourceType: "secret"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
}

// ── filter by user ID ─────────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByUserID(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(8, "user.updated")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.UserID != nil && *f.UserID == uint(42)
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{UserID: 42})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── filter by resource ID ─────────────────────────────────────────────────────

func TestSearchAuditLogs_FilterByResourceID(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(9, "secret.read")}
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.SecretID != nil && *f.SecretID == uint(99)
	})).Return(events, int64(1), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{ResourceID: 99})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
}

// ── limit/offset pagination ───────────────────────────────────────────────────

func TestSearchAuditLogs_LimitOffset(t *testing.T) {
	c, ms := setupSearchCore(t)
	events := []*models.AuditEvent{mockAuditEvent(6, "secret.read")}
	// With limit=10 and offset=10 → page = 10/10 + 1 = 2, pageSize = 10.
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.PageSize == 10 && f.Page == 2
	})).Return(events, int64(11), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Limit: 10, Offset: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(11), result.Total)
	assert.Len(t, result.Events, 1)
}

// ── limit > 1000 → capped ────────────────────────────────────────────────────

func TestSearchAuditLogs_LimitCappedAt1000(t *testing.T) {
	c, ms := setupSearchCore(t)
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		// PageSize must be capped to 1000, never 5000.
		return f.PageSize == 1000
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Limit: 5000})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
}

// ── default limit 100 when Limit == 0 ────────────────────────────────────────

func TestSearchAuditLogs_DefaultLimit(t *testing.T) {
	c, ms := setupSearchCore(t)
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.PageSize == 100
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ── empty result → {events:[], total:0} ──────────────────────────────────────

func TestSearchAuditLogs_EmptyResult(t *testing.T) {
	c, ms := setupSearchCore(t)
	ms.On("GetAuditLogs", mock.Anything, mock.Anything).Return([]*models.AuditEvent{}, int64(0), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Events)
}

// ── nil events from storage → normalised to empty slice ──────────────────────

func TestSearchAuditLogs_NilEventsNormalised(t *testing.T) {
	c, ms := setupSearchCore(t)
	ms.On("GetAuditLogs", mock.Anything, mock.Anything).Return(nil, int64(0), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{})
	require.NoError(t, err)
	assert.NotNil(t, result.Events)
	assert.Empty(t, result.Events)
}

// ── inverted time range returns error ─────────────────────────────────────────

func TestSearchAuditLogs_InvertedTimeRange(t *testing.T) {
	c, _ := setupSearchCore(t)
	since := time.Now()
	until := time.Now().Add(-time.Hour) // until < since

	_, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Since: since, Until: until})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "until must not be before since")
}

// ── storage error propagates ──────────────────────────────────────────────────

func TestSearchAuditLogs_StorageError(t *testing.T) {
	c, ms := setupSearchCore(t)
	ms.On("GetAuditLogs", mock.Anything, mock.Anything).Return(nil, int64(0), errors.New("db gone"))

	_, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db gone")
}

// ── since-only (no until) still passes ───────────────────────────────────────

func TestSearchAuditLogs_SinceOnly(t *testing.T) {
	c, ms := setupSearchCore(t)
	since := time.Now().Add(-time.Hour)
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.StartTime != nil && f.EndTime == nil
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Since: since})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ── offset=0 → page=1 ────────────────────────────────────────────────────────

func TestSearchAuditLogs_ZeroOffsetIsPage1(t *testing.T) {
	c, ms := setupSearchCore(t)
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		return f.Page == 1
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	result, err := c.SearchAuditLogs(context.Background(), AuditSearchRequest{Limit: 50, Offset: 0})
	require.NoError(t, err)
	assert.NotNil(t, result)
}
