// info_rune_test.go — exercises infoCmd.RunE directly (info_remote_test.go only
// tests fetchInfo and the orDefault/boolWord helpers).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetInfoFlags(t *testing.T) {
	t.Helper()
	orig := infoID
	t.Cleanup(func() { infoID = orig })
}

func TestInfoCmd_MissingID(t *testing.T) {
	resetInfoFlags(t)
	infoID = 0
	err := infoCmd.RunE(infoCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestInfoCmd_NoServer(t *testing.T) {
	resetInfoFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	infoID = 7
	err := infoCmd.RunE(infoCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestInfoCmd_Success_FullFields(t *testing.T) {
	resetInfoFlags(t)
	_, done := infoStub(t)
	defer done()
	infoID = 7

	out := captureStdoutForFolder(t, func() {
		err := infoCmd.RunE(infoCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Secret 7: db")
	assert.Contains(t, out, "confidential")
	assert.Contains(t, out, "user #3")
	assert.Contains(t, out, "yes")
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "prod, tier1")
	assert.Contains(t, out, "prod DB")
}

func TestInfoCmd_Success_TagsFetchFails_BestEffort(t *testing.T) {
	resetInfoFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/7" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"ID":7,"Name":"db","Type":"password"}}`))
			return
		}
		// /api/v1/secrets/7/tags errors — must not fail the whole summary.
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	_ = rc
	infoID = 7

	out := captureStdoutForFolder(t, func() {
		err := infoCmd.RunE(infoCmd, nil)
		require.NoError(t, err, "a failed best-effort tags fetch must not fail the summary")
	})
	assert.Contains(t, out, "Secret 7: db")
	assert.Contains(t, out, "unclassified")
	assert.Contains(t, out, "—")
}

func TestInfoCmd_FetchInfoError(t *testing.T) {
	resetInfoFlags(t)
	_, done := infoStub(t)
	defer done()
	infoID = 999

	err := infoCmd.RunE(infoCmd, nil)
	require.Error(t, err)
}
