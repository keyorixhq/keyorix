package hygiene

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hygieneStub(t *testing.T, body string) (*common.RemoteClient, func(), *string) {
	t.Helper()
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/hygiene" {
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close, &gotQuery
}

func TestFetchDeploymentHygiene(t *testing.T) {
	const body = `{"data":{"totals":{"orphaned_secrets":1,"unused_secrets":3,"expiring_secrets":2,"stale_machine_identities":0,"rotation_overdue":1},"projects":[{"project_id":7,"project_name":"web","orphaned_secrets":1,"unused_secrets":2,"expiring_secrets":1,"stale_machine_identities":0,"rotation_overdue":1}]}}`
	rc, done, _ := hygieneStub(t, body)
	defer done()

	r, err := fetchDeploymentHygiene(context.Background(), rc, 0, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Totals.OrphanedSecrets)
	assert.Equal(t, 3, r.Totals.UnusedSecrets)
	require.Len(t, r.Projects, 1)
	assert.Equal(t, uint(7), r.Projects[0].ProjectID)
	assert.Equal(t, "web", r.Projects[0].ProjectName)
	assert.Equal(t, 1, r.Projects[0].RotationOverdue)
}

func TestFetchDeploymentHygiene_PassesWindows(t *testing.T) {
	rc, done, gotQuery := hygieneStub(t, `{"data":{"totals":{},"projects":[]}}`)
	defer done()

	_, err := fetchDeploymentHygiene(context.Background(), rc, 30, 7, 60)
	require.NoError(t, err)
	// Only positive windows are sent; zero ones are omitted.
	assert.Contains(t, *gotQuery, "unused_days=30")
	assert.Contains(t, *gotQuery, "expiring_days=7")
	assert.Contains(t, *gotQuery, "stale_days=60")
}

func TestFetchDeploymentHygiene_OmitsZeroWindows(t *testing.T) {
	rc, done, gotQuery := hygieneStub(t, `{"data":{"totals":{},"projects":[]}}`)
	defer done()

	_, err := fetchDeploymentHygiene(context.Background(), rc, 0, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, *gotQuery, "no window flags → no query string")
}
