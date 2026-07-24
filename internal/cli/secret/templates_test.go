package secret

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tmplStub starts a stub server and returns a configured RemoteClient.
func tmplStub(t *testing.T, handle http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handle)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

const tmplListJSON = `{"data":{"templates":[
	{"id":1,"name":"db-secret","description":"Database credentials","default_classification":"confidential","default_tags":"db","rotation_hint_days":90},
	{"id":2,"name":"api-key","description":"Third-party API key","default_classification":"restricted","default_tags":"api","rotation_hint_days":30}
]}}`

// ── list ──────────────────────────────────────────────────────────────────────

func TestRunTemplateList_Empty(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/secret-templates", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"templates":[]}}`))
	})
	defer done()

	require.NoError(t, runTemplateList(context.Background(), rc))
}

func TestRunTemplateList_WithTemplates(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(tmplListJSON))
	})
	defer done()

	require.NoError(t, runTemplateList(context.Background(), rc))
}

func TestRunTemplateList_ServerError(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer done()

	err := runTemplateList(context.Background(), rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list templates")
}

// ── get ───────────────────────────────────────────────────────────────────────

func TestRunTemplateGet_Found(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(tmplListJSON))
	})
	defer done()

	require.NoError(t, runTemplateGet(context.Background(), rc, "db-secret"))
}

func TestRunTemplateGet_NotFound(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"templates":[]}}`))
	})
	defer done()

	err := runTemplateGet(context.Background(), rc, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunTemplateGet_ServerError(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	defer done()

	err := runTemplateGet(context.Background(), rc, "anything")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get template")
}

// ── create ────────────────────────────────────────────────────────────────────

func TestRunTemplateCreate(t *testing.T) {
	var gotBody map[string]any
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":7,"name":"my-tmpl","description":"desc"}}`))
	})
	defer done()

	origName := tmplName
	defer func() { tmplName = origName }()
	tmplName = "my-tmpl"
	tmplDescription = "desc"
	tmplClassification = "confidential"
	tmplTags = "db"
	tmplRotationDays = 90

	require.NoError(t, runTemplateCreate(context.Background(), rc))
	assert.Equal(t, "my-tmpl", gotBody["name"])
	assert.Equal(t, "desc", gotBody["description"])
}

func TestRunTemplateCreate_ServerError(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	})
	defer done()

	origName := tmplName
	defer func() { tmplName = origName }()
	tmplName = "bad-tmpl"

	err := runTemplateCreate(context.Background(), rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create template")
}

// ── delete ────────────────────────────────────────────────────────────────────

func TestRunTemplateDelete_Found(t *testing.T) {
	var deletedPath string
	calls := 0
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(tmplListJSON))
			return
		}
		// DELETE
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	defer done()

	require.NoError(t, runTemplateDelete(context.Background(), rc, "db-secret"))
	assert.Equal(t, "/api/v1/secret-templates/1", deletedPath)
	assert.Equal(t, 2, calls)
}

func TestRunTemplateDelete_NotFound(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"templates":[]}}`))
	})
	defer done()

	err := runTemplateDelete(context.Background(), rc, "ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunTemplateDelete_ListError(t *testing.T) {
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer done()

	err := runTemplateDelete(context.Background(), rc, "any")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list templates")
}

func TestRunTemplateDelete_DeleteError(t *testing.T) {
	calls := 0
	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(tmplListJSON))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	defer done()

	err := runTemplateDelete(context.Background(), rc, "api-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete template")
}

// ── RunE closure coverage ──────────────────────────────────────────────────────
//
// Each cobra command's RunE closure is only executed when cobra dispatches the
// command.  We invoke cmd.RunE directly so the coverage tool registers those
// lines without spinning up the full CLI binary.

// TestTemplateListCmd_NoServer exercises the !ok branch in templateListCmd.RunE.
func TestTemplateListCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := templateListCmd.RunE(templateListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestTemplateGetCmd_NoServer exercises the !ok branch in templateGetCmd.RunE.
func TestTemplateGetCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := templateGetCmd.RunE(templateGetCmd, []string{"some-name"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestTemplateCreateCmd_NoName exercises the empty-name guard in templateCreateCmd.RunE.
func TestTemplateCreateCmd_NoName(t *testing.T) {
	orig := tmplName
	defer func() { tmplName = orig }()
	tmplName = ""
	err := templateCreateCmd.RunE(templateCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name is required")
}

// TestTemplateCreateCmd_NoServer exercises the !ok branch in templateCreateCmd.RunE.
func TestTemplateCreateCmd_NoServer(t *testing.T) {
	orig := tmplName
	defer func() { tmplName = orig }()
	tmplName = "some-tpl"
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := templateCreateCmd.RunE(templateCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestTemplateDeleteCmd_NoServer exercises the !ok branch in templateDeleteCmd.RunE.
func TestTemplateDeleteCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := templateDeleteCmd.RunE(templateDeleteCmd, []string{"some-name"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestRunTemplateGet_MarshalError exercises the json.MarshalIndent error path in
// runTemplateGet. Because models.SecretTemplate contains only serialisable
// types, this path is dead code in production; we reach it by injecting a
// failing marshaler via the package-level jsonMarshalIndentFn variable.
func TestRunTemplateGet_MarshalError(t *testing.T) {
	orig := jsonMarshalIndentFn
	jsonMarshalIndentFn = func(_ interface{}, _, _ string) ([]byte, error) {
		return nil, errors.New("forced marshal failure")
	}
	defer func() { jsonMarshalIndentFn = orig }()

	rc, done := tmplStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(tmplListJSON))
	})
	defer done()

	err := runTemplateGet(context.Background(), rc, "db-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal template")
}
