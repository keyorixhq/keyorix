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

// AUDIT-UX-2 item 3 (#2951 follow-up): `keyorix secret delete` wrote a
// secret.read audit row (and a "read" access-log row) for the secret it was
// deleting, because the CLI prints the version count via GET
// /secrets/{id}/versions and that listing was audited as a value read. It
// exposes no value (SecretVersion.EncryptedValue is json:"-"). Listing versions
// is now its own event, secret.versions_listed, so secret.read (and every read
// count, billing, usage and anomaly read baseline keyed on it or on access-log
// action "read") means a value disclosure only.
//
// This replays the CLI's exact request sequence (cli/cmd/secret_crud.go
// runSecretDelete: GET /secrets/{id}?include_value=false, GET
// /secrets/{id}/versions, DELETE /secrets/{id}) against the real router.
func TestCLISecretDeleteFlow_WritesNoSecretRead(t *testing.T) {
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

	st, body := do(http.MethodPost, "/api/v1/secrets", `{"name":"versions-listed-delete","value":"v1","project_id":1,"environment_id":1,"type":"password"}`)
	require.Equal(t, http.StatusCreated, st, string(body))
	var created struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	id := created.Data.ID
	require.NotZero(t, id)

	// The CLI delete flow.
	st, body = do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=false", id), "")
	require.Equal(t, http.StatusOK, st, string(body))
	st, body = do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions", id), "")
	require.Equal(t, http.StatusOK, st, string(body))
	assert.NotContains(t, string(body), "v1", "the versions listing must not carry the value")
	st, body = do(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), "")
	require.Equal(t, http.StatusNoContent, st, string(body))

	ctx := context.Background()
	count := func(eventType string) int {
		t.Helper()
		et, sid := eventType, id
		events, _, err := c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &et, SecretID: &sid, PageSize: 100})
		require.NoError(t, err)
		return len(events)
	}
	assert.Equal(t, 0, count("secret.read"), "deleting a secret via the CLI flow must not record a secret.read (no value was disclosed)")
	assert.Equal(t, 1, count("secret.versions_listed"), "the versions listing is still audited, as secret.versions_listed")

	logs, err := c.Storage().ListSecretAccessLogs(ctx, id, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	actions := map[string]int{}
	for _, l := range logs {
		actions[l.Action]++
	}
	assert.Zero(t, actions["read"], "no access-log \"read\" row (read counts, total reads and usage reports count those): %v", actions)
	assert.Equal(t, 1, actions["versions_list"], "the listing keeps an access-log row so anomaly detection (which reads every action) still sees who enumerated versions from where: %v", actions)
}
