package secret

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoreSetup creates a test HTTP server driven by handler and points the CLI at
// it via env vars. It returns the RemoteClient and a cleanup function.
func scoreSetup(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")
	// Reset package-level flag vars so tests don't bleed into each other.
	t.Cleanup(func() {
		scoreProject = ""
		scoreEnv = 0
	})
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// captureScoreOutput captures both stdout and stderr produced by fn.
func captureScoreOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	// Capture stdout.
	origOut := os.Stdout
	rOut, wOut, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = wOut

	// Capture stderr.
	origErr := os.Stderr
	rErr, wErr, err2 := os.Pipe()
	require.NoError(t, err2)
	os.Stderr = wErr

	defer func() {
		os.Stdout = origOut
		os.Stderr = origErr
	}()

	fn()

	require.NoError(t, wOut.Close())
	require.NoError(t, wErr.Close())

	outBytes, _ := io.ReadAll(rOut)
	errBytes, _ := io.ReadAll(rErr)

	var buf bytes.Buffer
	buf.Write(outBytes)
	stdout = buf.String()
	stderr = string(errBytes)
	return
}

// highRiskHandler serves:
//   - GET /api/v1/secrets?...  → list with one secret named "prod-db"
//   - GET /api/v1/secrets/5/risk → high-risk score
func highRiskHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/secrets":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":5,"Name":"prod-db"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
	case "/api/v1/secrets/5/risk":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":5,"secret_name":"prod-db","score":85,"band":"high","factors":[{"key":"rotation","label":"Rotation age","score":100,"weight":0.3,"detail":"Last created 400 day(s) ago (never rotated)"},{"key":"expiry","label":"Expiry","score":100,"weight":0.3,"detail":"Expired 10 day(s) ago"},{"key":"usage","label":"Usage","score":80,"weight":0.2,"detail":"No reads in the last 30 days"},{"key":"exposure","label":"Exposure","score":10,"weight":0.2,"detail":"Only the owner has access"}],"degraded":false}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSecretScore_Remote_HighRisk(t *testing.T) {
	rc, done := scoreSetup(t, highRiskHandler)
	defer done()

	var runErr error
	stdout, stderr := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "prod-db")
	})
	require.NoError(t, runErr)

	// Output should show the secret name, score, and band.
	assert.Contains(t, stdout, "prod-db")
	assert.Contains(t, stdout, "85/100")
	assert.Contains(t, stdout, "HIGH")
	assert.Contains(t, stdout, "Factors:")
	assert.Contains(t, stdout, "rotation")

	// HIGH risk warning must go to stderr.
	assert.Contains(t, stderr, "HIGH risk")
	assert.Contains(t, stderr, "Consider rotating")
}

// lowRiskHandler serves a low-risk score for secret "jwt-key" (id=3).
func lowRiskHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/secrets":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":3,"Name":"jwt-key"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
	case "/api/v1/secrets/3/risk":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":3,"secret_name":"jwt-key","score":12,"band":"low","factors":[{"key":"rotation","label":"Rotation age","score":10,"weight":0.3,"detail":"Last rotated 5 day(s) ago"},{"key":"expiry","label":"Expiry","score":10,"weight":0.3,"detail":"Expires in 200 day(s)"},{"key":"usage","label":"Usage","score":10,"weight":0.2,"detail":"12 reads in the last 30 days"},{"key":"exposure","label":"Exposure","score":10,"weight":0.2,"detail":"Only the owner has access"}],"degraded":false}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSecretScore_Remote_LowRisk(t *testing.T) {
	rc, done := scoreSetup(t, lowRiskHandler)
	defer done()

	var runErr error
	stdout, stderr := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "jwt-key")
	})
	require.NoError(t, runErr)

	assert.Contains(t, stdout, "jwt-key")
	assert.Contains(t, stdout, "12/100")
	assert.Contains(t, stdout, "LOW")

	// No HIGH-risk warning for a low-risk secret.
	assert.NotContains(t, stderr, "HIGH risk")
}

// notFoundHandler responds to all requests with 404.
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/secrets":
		// Return an empty list so name resolution fails gracefully.
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":500,"total_pages":1}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"error":"NotFound","message":"not found","code":404}`))
	}
}

func TestSecretScore_Remote_NotFound(t *testing.T) {
	rc, done := scoreSetup(t, notFoundHandler)
	defer done()

	err := runScoreRemote(t.Context(), rc, "ghost-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
