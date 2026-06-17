package k8ssync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSink points a RESTSink at an httptest server (same package, so we set fields
// directly rather than going through the in-cluster constructor).
func testSink(srv *httptest.Server) *RESTSink {
	return &RESTSink{host: srv.URL, token: "tok", fieldManager: "keyorix-sync", hc: srv.Client()}
}

func TestRESTSink_GetAbsentReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	data, err := testSink(srv).Get(context.Background(), "app", "creds")
	require.NoError(t, err)
	assert.Nil(t, data, "an absent Secret returns (nil, nil) so the engine treats it as create")
}

func TestRESTSink_GetDecodesData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/namespaces/app/secrets/creds", r.URL.Path)
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{"DB":"` + base64.StdEncoding.EncodeToString([]byte("p4ss")) + `"}}`))
	}))
	defer srv.Close()

	data, err := testSink(srv).Get(context.Background(), "app", "creds")
	require.NoError(t, err)
	assert.Equal(t, []byte("p4ss"), data["DB"])
}

func TestRESTSink_ApplyServerSideApply(t *testing.T) {
	var gotMethod, gotCT, gotFM string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotFM = r.URL.Query().Get("fieldManager")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"DB": []byte("p4ss")})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPatch, gotMethod)
	assert.Equal(t, "application/apply-patch+yaml", gotCT)
	assert.Equal(t, "keyorix-sync", gotFM)
	assert.Equal(t, "Secret", gotBody["kind"])
	// Value is base64-encoded in the Secret's data map.
	data := gotBody["data"].(map[string]interface{})
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("p4ss")), data["DB"])
}

func TestRESTSink_ApplyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"K": []byte("v")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403")
}

// End-to-end through the engine: the REST sink plays the K8s side while a fake
// fetcher plays Keyorix, proving the seams compose.
func TestRESTSink_WithEngine(t *testing.T) {
	applied := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound) // nothing exists yet → create
			return
		}
		applied[r.URL.Path] = true
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer srv.Close()

	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	res, err := NewEngine(f, testSink(srv)).Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created)
	assert.True(t, applied["/api/v1/namespaces/app/secrets/creds"])
}
