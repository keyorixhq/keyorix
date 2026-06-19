package machine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mtHygieneStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/machine-token-hygiene" {
			_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":2,"machine_identity_id":5,"name":"ci","token_prefix":"kx_machine_ci","last_used_at":"","expired":false,"stale":true},{"id":7,"machine_identity_id":9,"name":"old","token_prefix":"kx_machine_old","expired":true,"stale":false}],"total":2}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestFetchMachineTokenHygiene(t *testing.T) {
	rc, done := mtHygieneStub(t)
	defer done()
	rows, err := fetchMachineTokenHygiene(context.Background(), rc, 30)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "ci", rows[0].Name)
	assert.True(t, rows[0].Stale)
	assert.Equal(t, uint(9), rows[1].MachineIdentityID)
	assert.True(t, rows[1].Expired)
}

func TestMachineFlagLabel(t *testing.T) {
	assert.Equal(t, "stale", machineFlagLabel(machineTokenHygieneRow{Stale: true}))
	assert.Equal(t, "expired", machineFlagLabel(machineTokenHygieneRow{Expired: true}))
	assert.Equal(t, "exp,stale", machineFlagLabel(machineTokenHygieneRow{Expired: true, Stale: true}))
}
