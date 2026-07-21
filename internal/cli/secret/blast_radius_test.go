package secret

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blastRadiusStub starts a test HTTP server that serves blast-radius responses
// for secret IDs 7 (has dependents) and 8 (no dependents).
func blastRadiusStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/7/blast-radius":
			_, _ = w.Write([]byte(`{"data":{"source_secret_id":7,"source_secret_name":"db-password","dependents":[{"secret_id":10,"secret_name":"app-token","project_id":1,"owner_id":5,"depth":1,"risk_level":"high"},{"secret_id":11,"secret_name":"edge-cert","project_id":1,"owner_id":6,"depth":2,"risk_level":"medium"}],"total_impact":2,"max_depth":2}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/8/blast-radius":
			_, _ = w.Write([]byte(`{"data":{"source_secret_id":8,"source_secret_name":"standalone","dependents":[],"total_impact":0,"max_depth":0}}`))
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

func TestFetchBlastRadius_WithDependents(t *testing.T) {
	rc, done := blastRadiusStub(t)
	defer done()
	report, err := fetchBlastRadius(context.Background(), rc, 7)
	require.NoError(t, err)
	assert.Equal(t, uint(7), report.SourceSecretID)
	assert.Equal(t, "db-password", report.SourceSecretName)
	assert.Equal(t, 2, report.TotalImpact)
	assert.Equal(t, 2, report.MaxDepth)
	require.Len(t, report.Dependents, 2)
	assert.Equal(t, uint(10), report.Dependents[0].SecretID)
	assert.Equal(t, "app-token", report.Dependents[0].SecretName)
	assert.Equal(t, "high", report.Dependents[0].RiskLevel)
	assert.Equal(t, 1, report.Dependents[0].Depth)
	assert.Equal(t, uint(5), report.Dependents[0].OwnerID)
	assert.Equal(t, "medium", report.Dependents[1].RiskLevel)
	assert.Equal(t, 2, report.Dependents[1].Depth)
}

func TestFetchBlastRadius_NoDependents(t *testing.T) {
	rc, done := blastRadiusStub(t)
	defer done()
	report, err := fetchBlastRadius(context.Background(), rc, 8)
	require.NoError(t, err)
	assert.Equal(t, 0, report.TotalImpact)
	assert.Empty(t, report.Dependents)
}

func TestPrintBlastRadius_NoDependents(t *testing.T) {
	report := &blastRadiusReportView{
		SourceSecretID:   8,
		SourceSecretName: "standalone",
		Dependents:       []blastRadiusNodeView{},
		TotalImpact:      0,
		MaxDepth:         0,
	}
	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printBlastRadius(report)
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	os.Stdout = old

	assert.Contains(t, buf.String(), "No dependents")
	assert.Contains(t, buf.String(), "standalone")
}

func TestPrintBlastRadius_WithDependents(t *testing.T) {
	report := &blastRadiusReportView{
		SourceSecretID:   7,
		SourceSecretName: "db-password",
		Dependents: []blastRadiusNodeView{
			{SecretID: 10, SecretName: "app-token", ProjectID: 1, OwnerID: 5, Depth: 1, RiskLevel: "high"},
			{SecretID: 11, SecretName: "edge-cert", ProjectID: 1, OwnerID: 6, Depth: 2, RiskLevel: "medium"},
		},
		TotalImpact: 2,
		MaxDepth:    2,
	}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printBlastRadius(report)
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	os.Stdout = old

	out := buf.String()
	assert.Contains(t, out, "db-password")
	assert.Contains(t, out, "2 dependent(s)")
	assert.Contains(t, out, "app-token")
	assert.Contains(t, out, "high")
	assert.Contains(t, out, "edge-cert")
	assert.Contains(t, out, "medium")
}

func TestBlastRadiusClient_NoServer(t *testing.T) {
	// Unset server env so NewRemoteClient returns false.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	_, err := blastRadiusClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestBlastRadiusClient_HappyPath(t *testing.T) {
	// With server env set, blastRadiusClient should return a client without error.
	_, done := blastRadiusStub(t)
	defer done()
	c, err := blastRadiusClient()
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestFetchBlastRadius_HTTPError(t *testing.T) {
	// Use a stub that returns 404 for unknown paths.
	_, done := blastRadiusStub(t)
	defer done()
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	// Request a non-existent secret ID → stub returns 404.
	_, err := fetchBlastRadius(context.Background(), rc, 9999)
	require.Error(t, err)
}
