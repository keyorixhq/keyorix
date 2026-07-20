package compliance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialTrendsCmd_Success(t *testing.T) {
	t.Cleanup(func() { credTrendDays = 30 })

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/credential-trends", r.URL.Path)
		assert.Equal(t, "30", r.URL.Query().Get("days"))
		_, _ = w.Write([]byte(`{"data":{
			"days":30,
			"points":[
				{"date":"2026-06-01T00:00:00Z","stale_pats":2,"expired_pats":1,"stale_machines":0,"total_pats":10,"total_machines":3},
				{"date":"2026-06-02T00:00:00Z","stale_pats":3,"expired_pats":1,"stale_machines":1,"total_pats":10,"total_machines":3}
			]
		}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, credentialTrendsCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "last 30 days")
	assert.Contains(t, out, "Date")
	assert.Contains(t, out, "StalePATs")
	assert.Contains(t, out, "2026-06-01")
}

func TestCredentialTrendsCmd_60Days(t *testing.T) {
	t.Cleanup(func() { credTrendDays = 30 })
	credTrendDays = 60

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "60", r.URL.Query().Get("days"))
		_, _ = w.Write([]byte(`{"data":{"days":60,"points":[]}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, credentialTrendsCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "last 60 days")
}

func TestCredentialTrendsCmd_InvalidDaysDefaultsTo30(t *testing.T) {
	t.Cleanup(func() { credTrendDays = 30 })
	credTrendDays = 45 // invalid — should fall back to 30

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "30", r.URL.Query().Get("days"))
		_, _ = w.Write([]byte(`{"data":{"days":30,"points":[]}}`))
	})

	require.NoError(t, credentialTrendsCmd.RunE(nil, nil))
	assert.Equal(t, 30, credTrendDays)
}

func TestCredentialTrendsCmd_NotConnected(t *testing.T) {
	t.Cleanup(func() { credTrendDays = 30 })
	setupDisconnected(t)

	err := credentialTrendsCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestCredentialTrendsCmd_ServerError(t *testing.T) {
	t.Cleanup(func() { credTrendDays = 30 })

	setupRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := credentialTrendsCmd.RunE(nil, nil)
	require.Error(t, err)
}
