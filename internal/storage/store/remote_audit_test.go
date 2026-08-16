package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- LogAuditEvent ---

func TestRemoteStorage_LogAuditEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/audit/event", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	event := &models.AuditEvent{
		EventType: "secret.read",
		ActorType: "user",
	}
	err = rs.LogAuditEvent(context.Background(), event)
	require.NoError(t, err)
}

// --- CreateSecretAccessLog (no-op) ---

func TestRemoteStorage_CreateSecretAccessLog(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.CreateSecretAccessLog(context.Background(), &models.SecretAccessLog{})
	require.NoError(t, err)
}

// --- CountImpersonatedActions (returns 0) ---

func TestRemoteStorage_CountImpersonatedActions(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	count, err := rs.CountImpersonatedActions(context.Background(), 1, 2, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// --- GetAuditLogs ---

func TestRemoteStorage_GetAuditLogs_NilFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/audit/logs", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"events": []map[string]interface{}{
				{"EventType": "secret.read", "ActorType": "user"},
			},
			"total": 1,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	events, total, err := rs.GetAuditLogs(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, events, 1)
}

func TestRemoteStorage_GetAuditLogs_WithFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/audit/logs", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"events": []map[string]interface{}{},
			"total":  int64(0),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	action := "secret.read"
	filter := &corestorage.AuditFilter{
		Action:   &action,
		Page:     1,
		PageSize: 10,
	}
	events, total, err := rs.GetAuditLogs(context.Background(), filter)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Len(t, events, 0)
}

// --- GetRBACAuditLogs ---

func TestRemoteStorage_GetRBACAuditLogs_NilFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/audit/rbac-logs", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"logs": []map[string]interface{}{
				{
					"id":      1,
					"action":  "role.assign",
					"success": true,
				},
			},
			"total": 1,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	logs, total, err := rs.GetRBACAuditLogs(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "role.assign", logs[0].Action)
}

func TestRemoteStorage_GetRBACAuditLogs_WithFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/audit/rbac-logs", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"logs":  []map[string]interface{}{},
			"total": int64(0),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	action := "role.assign"
	targetType := "project"
	filter := &corestorage.RBACAuditFilter{
		Action:     &action,
		TargetType: &targetType,
		Page:       1,
		PageSize:   10,
	}
	logs, total, err := rs.GetRBACAuditLogs(context.Background(), filter)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Len(t, logs, 0)
}

// --- ListSecretAccessLogs (unsupported) ---

func TestRemoteStorage_ListSecretAccessLogs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSecretAccessLogs(context.Background(), 1, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- CountSecretReadsBySecretIDs (unsupported) ---

func TestRemoteStorage_CountSecretReadsBySecretIDs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountSecretReadsBySecretIDs(context.Background(), []uint{1, 2}, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- PrincipalSecretFirstSeen (unsupported) ---

func TestRemoteStorage_PrincipalSecretFirstSeen_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.PrincipalSecretFirstSeen(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- MostAccessedSecrets (unsupported) ---

func TestRemoteStorage_MostAccessedSecrets_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.MostAccessedSecrets(context.Background(), nil, nil, time.Now(), 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- UnusedSecrets (unsupported) ---

func TestRemoteStorage_UnusedSecrets_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.UnusedSecrets(context.Background(), nil, nil, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- CountUnusedSecretsByProject (unsupported) ---

func TestRemoteStorage_CountUnusedSecretsByProject_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountUnusedSecretsByProject(context.Background(), []uint{1}, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- AuditRetentionStats (unsupported) ---

func TestRemoteStorage_AuditRetentionStats_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.AuditRetentionStats(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- VerifyAuditChain (unsupported) ---

func TestRemoteStorage_VerifyAuditChain_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.VerifyAuditChain(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- CreateAuditCheckpoint (unsupported) ---

func TestRemoteStorage_CreateAuditCheckpoint_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.CreateAuditCheckpoint(context.Background(), &models.AuditCheckpoint{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- LatestAuditCheckpoint (unsupported) ---

func TestRemoteStorage_LatestAuditCheckpoint_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.LatestAuditCheckpoint(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- UpdateAuditCheckpointAnchor (unsupported) ---

func TestRemoteStorage_UpdateAuditCheckpointAnchor_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.UpdateAuditCheckpointAnchor(context.Background(), 1, []byte("anchor"), time.Now(), "tsa-url")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- AuditEntryHashByID (unsupported) ---

func TestRemoteStorage_AuditEntryHashByID_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, _, err = rs.AuditEntryHashByID(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- GetSystemMetadata (unsupported) ---

func TestRemoteStorage_GetSystemMetadata_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, _, err = rs.GetSystemMetadata(context.Background(), "key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- SetSystemMetadata (unsupported) ---

func TestRemoteStorage_SetSystemMetadata_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.SetSystemMetadata(context.Background(), "key", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- CreateAnomalyAlert (unsupported) ---

func TestRemoteStorage_CreateAnomalyAlert_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.CreateAnomalyAlert(context.Background(), &models.AnomalyAlert{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- ListAnomalyAlerts (unsupported) ---

func TestRemoteStorage_ListAnomalyAlerts_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	acked := false
	_, err = rs.ListAnomalyAlerts(context.Background(), &acked)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- AcknowledgeAnomalyAlert (unsupported) ---

func TestRemoteStorage_AcknowledgeAnomalyAlert_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.AcknowledgeAnomalyAlert(context.Background(), 1, 2, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- ListUnalertedAnomalyAlerts (unsupported) ---

func TestRemoteStorage_ListUnalertedAnomalyAlerts_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListUnalertedAnomalyAlerts(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- MarkAnomalyAlertAlerted (unsupported) ---

func TestRemoteStorage_MarkAnomalyAlertAlerted_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.MarkAnomalyAlertAlerted(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- GetDistinctActiveUserIDs (unsupported) ---

func TestRemoteStorage_GetDistinctActiveUserIDs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetDistinctActiveUserIDs(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in remote mode")
}

// --- DeleteAuditLogsBefore (unsupported in remote mode) ---

func TestRemoteStorage_DeleteAuditLogsBefore_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	n, err := rs.DeleteAuditLogsBefore(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Equal(t, int64(0), n)
	assert.Contains(t, err.Error(), "not available in remote mode")
}
