// diff_test.go — remote httptest tests for the secret diff CLI command.
package secret

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// diffStub starts an httptest server that handles the by-name lookup and the
// diff endpoint. Returns a configured RemoteClient and a teardown function.
func diffStub(t *testing.T, secretID uint, fromV, toV int, diffBody string, diffStatus int) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// by-name resolution
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/by-name":
			_, _ = w.Write([]byte(`{"data":{"id":` + jsonUint(secretID) + `,"name":"my-api-key"}}`))

		// diff endpoint
		case r.Method == http.MethodGet &&
			r.URL.Path == diffEndpointPath(secretID, fromV, toV):
			w.WriteHeader(diffStatus)
			if diffBody != "" {
				_, _ = w.Write([]byte(diffBody))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok, "NewRemoteClient must succeed with env vars set")
	return rc, srv.Close
}

func diffEndpointPath(id uint, from, to int) string {
	return "/api/v1/secrets/" + jsonUint(id) + "/versions/" + jsonInt(from) + "/diff/" + jsonInt(to)
}

func jsonUint(v uint) string  { b, _ := json.Marshal(v); return string(b) }
func jsonInt(v int) string    { b, _ := json.Marshal(v); return string(b) }

// ── TestSecretDiff_Remote_Changes ─────────────────────────────────────────────

func TestSecretDiff_Remote_Changes(t *testing.T) {
	const (
		sid  = uint(42)
		from = 1
		to   = 3
	)
	body := `{"data":{` +
		`"secret_id":42,` +
		`"secret_name":"my-api-key",` +
		`"from_version":1,` +
		`"to_version":3,` +
		`"changes":[{"field":"classification","old_value":"(unknown)","new_value":"confidential"},` +
		`{"field":"read_count_delta","old_value":"3","new_value":"47 (+44)"}],` +
		`"acl_user_ids":[7,8]}}`

	rc, done := diffStub(t, sid, from, to, body, http.StatusOK)
	defer done()

	err := runDiffRemote(rc, "my-api-key", from, to)
	assert.NoError(t, err)
}

// ── TestSecretDiff_Remote_NoChanges ──────────────────────────────────────────

func TestSecretDiff_Remote_NoChanges(t *testing.T) {
	const (
		sid  = uint(7)
		from = 2
		to   = 3
	)
	body := `{"data":{` +
		`"secret_id":7,` +
		`"secret_name":"db-pass",` +
		`"from_version":2,` +
		`"to_version":3,` +
		`"changes":[],` +
		`"acl_user_ids":null}}`

	rc, done := diffStub(t, sid, from, to, body, http.StatusOK)
	defer done()

	err := runDiffRemote(rc, "db-pass", from, to)
	assert.NoError(t, err)
}

// ── TestSecretDiff_Remote_InvalidVersion ─────────────────────────────────────

func TestSecretDiff_Remote_InvalidVersion(t *testing.T) {
	const (
		sid  = uint(5)
		from = 1
		to   = 99 // doesn't exist on the server
	)
	errBody := `{"error":"NotFound","message":"version not found","code":404}`

	rc, done := diffStub(t, sid, from, to, errBody, http.StatusNotFound)
	defer done()

	err := runDiffRemote(rc, "my-api-key", from, to)
	require.Error(t, err, "a 404 from the diff endpoint must surface as an error")
}
