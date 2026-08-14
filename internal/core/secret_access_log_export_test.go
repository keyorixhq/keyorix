package core

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newExportCore(ms *MockStorage) *KeyorixCore {
	return NewKeyorixCore(ms)
}

func aSecret() *models.SecretNode {
	return &models.SecretNode{ID: 42, Name: "test-secret", ProjectID: 1, EnvironmentID: 2}
}

func anEvent(id uint, userID *uint, secretNodeID *uint, success *bool, actorType string) *models.AuditEvent {
	t := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return &models.AuditEvent{
		ID:           id,
		EventType:    exportAccessAction,
		UserID:       userID,
		SecretNodeID: secretNodeID,
		IPAddress:    "10.0.0.1",
		Success:      success,
		EventTime:    t,
		ActorType:    actorType,
	}
}

func ptrBool(b bool) *bool { return &b }
func ptrUint(u uint) *uint { return &u }

// Unsupported format returns an error.
func TestExportSecretAccessLog_InvalidFormat(t *testing.T) {
	ms := new(MockStorage)
	k := newExportCore(ms)

	_, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 1, "xlsx")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported export format")
}

// Secret not found returns "secret not found".
func TestExportSecretAccessLog_SecretNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(42)).Return(nil, errors.New("record not found"))
	k := newExportCore(ms)

	_, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 42, "json")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// GetAuditLogs error is propagated.
func TestExportSecretAccessLog_AuditLogError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(42)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 42, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return(nil, int64(0), errors.New("db timeout"))
	k := newExportCore(ms)

	_, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 42, "json")
	require.Error(t, err)
	require.Contains(t, err.Error(), "db timeout")
}

// JSON format returns application/json with valid JSON.
func TestExportSecretAccessLog_JSONFormat(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(42)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 42, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)
	uid := uint(7)
	events := []*models.AuditEvent{
		anEvent(101, &uid, ptrUint(42), ptrBool(true), "user"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return(events, int64(1), nil)
	k := newExportCore(ms)

	data, ct, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 42, "json")
	require.NoError(t, err)
	require.Contains(t, ct, "application/json")

	var rows []AccessLogExportRow
	require.NoError(t, json.Unmarshal(data, &rows))
	require.Len(t, rows, 1)
	require.Equal(t, uint(101), rows[0].EventID)
	require.Equal(t, uint(42), rows[0].SecretID)
	require.NotNil(t, rows[0].UserID)
	require.Equal(t, uint(7), *rows[0].UserID)
	require.True(t, rows[0].Success)
}

// CSV format returns text/csv with header + rows.
func TestExportSecretAccessLog_CSVFormat(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(42)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 42, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)
	uid := uint(5)
	events := []*models.AuditEvent{
		anEvent(202, &uid, ptrUint(42), ptrBool(false), "machine_identity"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return(events, int64(1), nil)
	k := newExportCore(ms)

	data, ct, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 42, ExportFormatCSV)
	require.NoError(t, err)
	require.Contains(t, ct, "text/csv")

	r := csv.NewReader(strings.NewReader(string(data)))
	records, err := r.ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2) // header + 1 row
	require.Equal(t, []string{"event_id", "secret_id", "user_id", "actor_type", "ip_address", "success", "event_time"}, records[0])
	require.Equal(t, "202", records[1][0])
	require.Equal(t, "5", records[1][2])
	require.Equal(t, "false", records[1][5])
}

// Event with nil UserID produces an empty user_id field in CSV.
func TestExportSecretAccessLog_NilUserID(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(42)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 42, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)
	events := []*models.AuditEvent{
		anEvent(303, nil, ptrUint(42), ptrBool(true), "system"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return(events, int64(1), nil)
	k := newExportCore(ms)

	data, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 42, ExportFormatCSV)
	require.NoError(t, err)

	r := csv.NewReader(strings.NewReader(string(data)))
	records, _ := r.ReadAll()
	require.Equal(t, "", records[1][2]) // user_id column is blank
}

// Event with nil Success is treated as success=true.
func TestExportSecretAccessLog_NilSuccess(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(42)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 42, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)
	events := []*models.AuditEvent{
		anEvent(404, nil, ptrUint(42), nil /* nil Success */, "user"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return(events, int64(1), nil)
	k := newExportCore(ms)

	data, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 42, ExportFormatJSON)
	require.NoError(t, err)

	var rows []AccessLogExportRow
	require.NoError(t, json.Unmarshal(data, &rows))
	require.True(t, rows[0].Success) // nil → true
}

// Event with nil SecretNodeID uses the secretID param for the row.
func TestExportSecretAccessLog_NilSecretNodeID(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(99)).Return(&models.SecretNode{ID: 99}, nil)
	stubAuthorizedSecretPrincipal(ms, 1, 99, Scope{}, permSecretsRead)
	events := []*models.AuditEvent{
		anEvent(505, nil, nil /* nil SecretNodeID */, ptrBool(true), "user"),
	}
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return(events, int64(1), nil)
	k := newExportCore(ms)

	data, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 99, ExportFormatJSON)
	require.NoError(t, err)

	var rows []AccessLogExportRow
	require.NoError(t, json.Unmarshal(data, &rows))
	require.Equal(t, uint(99), rows[0].SecretID) // falls back to secretID param
}

// Empty event list returns an empty JSON array.
func TestExportSecretAccessLog_EmptyEvents(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 1, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)
	ms.On("GetAuditLogs", mock.Anything, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{}, int64(0), nil)
	k := newExportCore(ms)

	data, ct, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 1, ExportFormatJSON)
	require.NoError(t, err)
	require.Contains(t, ct, "application/json")
	require.Equal(t, "[]", strings.TrimSpace(string(data)))
}

// The AuditFilter passed to storage has SecretID + Action set correctly.
func TestExportSecretAccessLog_FilterParams(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(77)).Return(aSecret(), nil)
	stubAuthorizedSecretPrincipal(ms, 1, 77, Scope{ProjectID: 1, EnvironmentID: 2}, permSecretsRead)

	var capturedFilter *storage.AuditFilter
	ms.On("GetAuditLogs", mock.Anything, mock.MatchedBy(func(f *storage.AuditFilter) bool {
		capturedFilter = f
		return true
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	k := newExportCore(ms)
	_, _, err := k.ExportSecretAccessLog(context.Background(), ActorTypeUser, 1, 77, ExportFormatJSON)
	require.NoError(t, err)

	require.NotNil(t, capturedFilter)
	require.Equal(t, uint(77), *capturedFilter.SecretID)
	require.Equal(t, exportAccessAction, *capturedFilter.Action)
	require.Equal(t, ExportMaxRows, capturedFilter.PageSize)
	require.True(t, capturedFilter.Ascending)
}
