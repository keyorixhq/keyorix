package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func auditStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/7/audit":
			_, _ = w.Write([]byte(`{"data":{"audit":[{"id":3,"event_type":"secret.suspended","timestamp":"2026-06-18T12:00:00Z","actor_type":"user","user_id":1,"description":"frozen for incident"},{"id":2,"event_type":"secret.rotated","timestamp":"2026-06-18T11:00:00Z","actor_type":"user","user_id":1,"description":""},{"id":1,"event_type":"secret.created","timestamp":"2026-06-18T10:00:00Z","actor_type":"user","user_id":1,"description":""}],"total":3}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestFetchAuditTrail(t *testing.T) {
	rc, done := auditStub(t)
	defer done()
	rows, err := fetchAuditTrail(context.Background(), rc, 7, 50)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, "secret.suspended", rows[0].EventType, "newest first")
	assert.Equal(t, "user", rows[0].ActorType)
	require.NotNil(t, rows[0].UserID)
	assert.Equal(t, uint(1), *rows[0].UserID)
	assert.Equal(t, "secret.created", rows[2].EventType)
}

func TestFetchAuditTrail_NotFound(t *testing.T) {
	rc, done := auditStub(t)
	defer done()
	_, err := fetchAuditTrail(context.Background(), rc, 999, 0)
	require.Error(t, err)
}
