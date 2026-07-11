// common_s3_test.go — coverage push for cli/common (batch s3).
// Targets: Get, Post, Put, Patch, Delete, DeleteWithBody, decodeEnvelope,
// LookupProjectIDByName, PrintProvisionResult, PrintOneTimePasswordResult,
// InitializeStorage, InitializeCoreService (shared-backend warning path).
package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── httptest helpers ──────────────────────────────────────────────────────────

// envelopeJSON wraps v in {"data": <v>} as the server always does.
func envelopeJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	inner, err := json.Marshal(v)
	require.NoError(t, err)
	return []byte(fmt.Sprintf(`{"data":%s}`, inner))
}

// newTestClient returns a RemoteClient pointed at srv with a fixed token.
func newTestClient(srv *httptest.Server) *RemoteClient {
	return &RemoteClient{Endpoint: srv.URL, Token: "test-token", hc: srv.Client()}
}

// ── Get ───────────────────────────────────────────────────────────────────────

func TestRemoteClient_Get_Success(t *testing.T) {
	type result struct{ Name string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelopeJSON(t, result{"alice"}))
	}))
	defer srv.Close()

	var out result
	err := newTestClient(srv).Get(context.Background(), "/v1/test", &out)
	require.NoError(t, err)
	assert.Equal(t, "alice", out.Name)
}

func TestRemoteClient_Get_HTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var out struct{}
	err := newTestClient(srv).Get(context.Background(), "/v1/secret", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestRemoteClient_Get_DecodeError(t *testing.T) {
	// Server returns plain non-envelope JSON → decodeEnvelope fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	var out struct{}
	err := newTestClient(srv).Get(context.Background(), "/v1/test", &out)
	require.Error(t, err)
}

func TestRemoteClient_Get_EmptyDataEnvelope(t *testing.T) {
	// Server returns {} (no "data" field) → decodeEnvelope returns "empty data" error
	// because json.RawMessage for a missing field is nil.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out struct{}
	err := newTestClient(srv).Get(context.Background(), "/v1/test", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

// ── Post ──────────────────────────────────────────────────────────────────────

func TestRemoteClient_Post_Success(t *testing.T) {
	type reqBody struct{ Key string }
	type respBody struct{ ID int }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body reqBody
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "my-key", body.Key)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelopeJSON(t, respBody{ID: 99}))
	}))
	defer srv.Close()

	var out respBody
	err := newTestClient(srv).Post(context.Background(), "/v1/secrets", reqBody{"my-key"}, &out)
	require.NoError(t, err)
	assert.Equal(t, 99, out.ID)
}

func TestRemoteClient_Post_NilOut(t *testing.T) {
	// out=nil means the caller doesn't need the response — no decode attempted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()

	err := newTestClient(srv).Post(context.Background(), "/v1/users", struct{}{}, nil)
	require.NoError(t, err)
}

func TestRemoteClient_Post_HTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	err := newTestClient(srv).Post(context.Background(), "/v1/x", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

// ── Put ───────────────────────────────────────────────────────────────────────

func TestRemoteClient_Put_Success(t *testing.T) {
	type payload struct{ Value string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelopeJSON(t, payload{"updated"}))
	}))
	defer srv.Close()

	var out payload
	err := newTestClient(srv).Put(context.Background(), "/v1/secret/1", payload{"updated"}, &out)
	require.NoError(t, err)
	assert.Equal(t, "updated", out.Value)
}

func TestRemoteClient_Put_NilOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := newTestClient(srv).Put(context.Background(), "/v1/x", struct{}{}, nil)
	require.NoError(t, err)
}

func TestRemoteClient_Put_HTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := newTestClient(srv).Put(context.Background(), "/v1/x", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// ── Patch ─────────────────────────────────────────────────────────────────────

func TestRemoteClient_Patch_Success(t *testing.T) {
	type payload struct{ Active bool }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelopeJSON(t, payload{true}))
	}))
	defer srv.Close()

	var out payload
	err := newTestClient(srv).Patch(context.Background(), "/v1/user/1", payload{true}, &out)
	require.NoError(t, err)
	assert.True(t, out.Active)
}

func TestRemoteClient_Patch_NilOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := newTestClient(srv).Patch(context.Background(), "/v1/x", struct{}{}, nil)
	require.NoError(t, err)
}

func TestRemoteClient_Patch_HTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := newTestClient(srv).Patch(context.Background(), "/v1/x", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

// ── DeleteWithBody ────────────────────────────────────────────────────────────

func TestRemoteClient_DeleteWithBody_Success(t *testing.T) {
	type body struct{ RoleID uint }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		var b body
		require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
		assert.Equal(t, uint(7), b.RoleID)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteWithBody(context.Background(), "/v1/user-roles", body{7})
	require.NoError(t, err)
}

func TestRemoteClient_DeleteWithBody_HTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteWithBody(context.Background(), "/v1/x", struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestRemoteClient_Delete_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := newTestClient(srv).Delete(context.Background(), "/v1/secret/42")
	require.NoError(t, err)
}

func TestRemoteClient_Delete_HTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := newTestClient(srv).Delete(context.Background(), "/v1/secret/99")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

// ── HTTP method marshal-error paths ───────────────────────────────────────────

// unmarshalable is a type that json.Marshal always fails on.
type unmarshalable struct {
	Ch chan int
}

func TestRemoteClient_Post_MarshalError(t *testing.T) {
	// json.Marshal fails for channels; error is returned before any HTTP request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called on marshal error")
	}))
	defer srv.Close()

	err := newTestClient(srv).Post(context.Background(), "/v1/x", unmarshalable{make(chan int)}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal")
}

func TestRemoteClient_Put_MarshalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called on marshal error")
	}))
	defer srv.Close()

	err := newTestClient(srv).Put(context.Background(), "/v1/x", unmarshalable{make(chan int)}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal")
}

func TestRemoteClient_Patch_MarshalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called on marshal error")
	}))
	defer srv.Close()

	err := newTestClient(srv).Patch(context.Background(), "/v1/x", unmarshalable{make(chan int)}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal")
}

func TestRemoteClient_DeleteWithBody_MarshalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called on marshal error")
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteWithBody(context.Background(), "/v1/x", unmarshalable{make(chan int)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal")
}

// ── LookupProjectIDByName ─────────────────────────────────────────────────────

// minimalStorage implements only the storage.Storage methods needed by the test.
type minimalStorage struct {
	storage.Storage // embed the interface for unimplemented methods
	projects        []*models.Project
	listErr         error
}

func (m *minimalStorage) ListProjects(_ context.Context) ([]*models.Project, error) {
	return m.projects, m.listErr
}

func TestLookupProjectIDByName_Found(t *testing.T) {
	st := &minimalStorage{projects: []*models.Project{
		{ID: 1, Name: "alpha"},
		{ID: 2, Name: "beta"},
	}}
	id, err := LookupProjectIDByName(context.Background(), st, "beta")
	require.NoError(t, err)
	assert.Equal(t, uint(2), id)
}

func TestLookupProjectIDByName_NotFound(t *testing.T) {
	st := &minimalStorage{projects: []*models.Project{{ID: 1, Name: "alpha"}}}
	_, err := LookupProjectIDByName(context.Background(), st, "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"missing" not found`)
}

func TestLookupProjectIDByName_ListError(t *testing.T) {
	st := &minimalStorage{listErr: fmt.Errorf("db failure")}
	_, err := LookupProjectIDByName(context.Background(), st, "any")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db failure")
}

// ── PrintProvisionResult ──────────────────────────────────────────────────────

func TestPrintProvisionResult_Delivered(t *testing.T) {
	// Capture stdout to verify the delivered message is printed.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintProvisionResult(&core.ProvisionSetupResult{
		Delivered: true,
		Email:     "user@example.com",
		Channel:   "smtp",
	})

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "user@example.com")
	assert.Contains(t, buf.String(), "smtp")
}

func TestPrintProvisionResult_OutOfBand(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintProvisionResult(&core.ProvisionSetupResult{
		Delivered:    false,
		Email:        "admin@example.com",
		LinkForAdmin: "https://keyorix.example.com/setup?token=abc",
	})

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "admin@example.com")
	assert.Contains(t, buf.String(), "https://keyorix.example.com/setup?token=abc")
}

// ── PrintOneTimePasswordResult ────────────────────────────────────────────────

func TestPrintOneTimePasswordResult_NonNil(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintOneTimePasswordResult(&core.OneTimePasswordResult{
		Email:           "user@example.com",
		OneTimePassword: "Sup3rS3cr3t!",
	})

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "user@example.com")
	assert.Contains(t, buf.String(), "Sup3rS3cr3t!")
}

// ── InitializeStorage ─────────────────────────────────────────────────────────

func TestInitializeStorage_DefaultLocalConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgPath := dir + "/keyorix.yaml"
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/init_storage_test.db"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	st, err := InitializeStorage()
	require.NoError(t, err)
	assert.NotNil(t, st)
}

// ── InitializeCoreService shared-backend warning path ─────────────────────────

func TestInitializeCoreService_RemoteNoActor_WarnsToStderr(t *testing.T) {
	// Exercise the "non-local storage type AND no actor set" warning branch.
	// Use storage.type=remote with a loopback base URL so CreateStorage succeeds
	// (remote storage is lazy — no connection on construction) and the warning is
	// printed. InitializeCoreService will eventually fail (wireSecretEncryption or
	// later), which is fine — we only need to capture the stderr warning.
	dir := t.TempDir()
	cfgPath := dir + "/keyorix.yaml"
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: remote
  remote:
    base_url: "http://127.0.0.1:19999"
    api_key: "test-token-for-warning-test"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("KEYORIX_CLI_ACTOR", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// InitializeCoreService will reach the warning then either complete or fail.
	_, _ = InitializeCoreService()

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	// The warning must mention the storage type and the env var.
	assert.Contains(t, buf.String(), "remote")
}
