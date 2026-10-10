package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// AUDIT-UX-3 item 1: GET /secrets/by-name returns metadata only (no value) but
// was audited as secret.read plus an access-log "read" row, inflating read
// summaries, billing/usage reads and total_reads. It is now its own event,
// secret.metadata_read, with access-log action "metadata_read" (same pattern as
// secret.versions_listed, #2970). A real value read still writes secret.read.
func TestGetSecretByName_AuditsMetadataReadNotRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	do := func(method, path, body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, b
	}

	st, body := do(http.MethodPost, "/api/v1/secrets", `{"name":"by-name-meta","value":"v1","project_id":1,"environment_id":1,"type":"password"}`)
	require.Equal(t, http.StatusCreated, st, string(body))
	var created struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	id := created.Data.ID
	require.NotZero(t, id)

	st, body = do(http.MethodGet, "/api/v1/secrets/by-name?name=by-name-meta&project_id=1&environment_id=1", "")
	require.Equal(t, http.StatusOK, st, string(body))
	assert.NotContains(t, string(body), "v1\"", "by-name must not carry the value")

	ctx := context.Background()
	count := func(eventType string) int {
		t.Helper()
		et, sid := eventType, id
		events, _, err := c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &et, SecretID: &sid, PageSize: 100})
		require.NoError(t, err)
		return len(events)
	}
	// The by-name audit write is fire-and-forget; wait for it to land.
	require.Eventually(t, func() bool {
		return count("secret.metadata_read")+count("secret.read") > 0
	}, 5*time.Second, 20*time.Millisecond, "by-name lookup must be audited")

	assert.Equal(t, 0, count("secret.read"), "a metadata-only lookup must not record a secret.read")
	assert.Equal(t, 1, count("secret.metadata_read"), "the lookup is still audited, as secret.metadata_read")

	logs, err := c.Storage().ListSecretAccessLogs(ctx, id, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	actions := map[string]int{}
	for _, l := range logs {
		actions[l.Action]++
	}
	assert.Zero(t, actions["read"], "no access-log \"read\" row: %v", actions)
	assert.Equal(t, 1, actions["metadata_read"], "anomaly detection (every action) still sees the lookup: %v", actions)

	// A real value read still counts as a read.
	st, body = do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), "")
	require.Equal(t, http.StatusOK, st, string(body))
	assert.Equal(t, 1, count("secret.read"), "a value read still writes secret.read")
}
