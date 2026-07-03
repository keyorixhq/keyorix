package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunExport_OutputFilePermissions guards #353: the plaintext export file
// must be created with 0600, like every sibling writer in this package
// (render.go, scan.go, fix.go), not the default os.Create mode.
func TestRunExport_OutputFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-permission bits don't apply on windows")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"default"}]}}`))
		case r.URL.Path == "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"development"}]}}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/secrets") && r.URL.Query().Get("project_id") != "":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":9,"name":"DB_PASSWORD"}]}}`))
		case r.URL.Path == "/api/v1/secrets/9":
			_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "secrets.env")

	origFormat, origOutput, origEnv, origProject := exportFormat, exportOutput, exportEnv, exportProject
	exportFormat = "dotenv"
	exportOutput = outPath
	exportEnv = "development"
	exportProject = "default"
	defer func() {
		exportFormat, exportOutput, exportEnv, exportProject = origFormat, origOutput, origEnv, origProject
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	require.NoError(t, runExport(cmd, nil))

	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "export output file must be created with 0600")

	data, err := os.ReadFile(outPath) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Contains(t, string(data), "DB_PASSWORD=s3cr3t")
}
