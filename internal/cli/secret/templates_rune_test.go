// templates_rune_test.go — covers the connected success-path line in each
// template RunE closure (the `return runTemplateXxx(...)` call itself), which
// templates_test.go never reaches: it tests runTemplateList/Get/Create/Delete
// directly and only drives the RunE closures down the NoServer/validation
// error branches, never through to a live stub server.
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func templatesRuneStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func TestTemplateListCmd_Success(t *testing.T) {
	done := templatesRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"templates":[]}}`))
	})
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := templateListCmd.RunE(templateListCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No templates found")
}

func TestTemplateGetCmd_Success(t *testing.T) {
	done := templatesRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"templates":[]}}`))
	})
	defer done()

	err := templateGetCmd.RunE(templateGetCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTemplateCreateCmd_Success(t *testing.T) {
	origName := tmplName
	t.Cleanup(func() { tmplName = origName })
	tmplName = "my-template"
	done := templatesRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"my-template"}}`))
	})
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := templateCreateCmd.RunE(templateCreateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "my-template")
}

func TestTemplateDeleteCmd_Success(t *testing.T) {
	done := templatesRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"templates":[]}}`))
	})
	defer done()

	err := templateDeleteCmd.RunE(templateDeleteCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
