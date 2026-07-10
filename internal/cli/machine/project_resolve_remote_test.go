package machine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveProjectContext_Remote is the regression for the double-{"data":…}
// envelope bug: rc.Get already strips the envelope, so the remote resolver must
// decode {"projects":[…]} directly. With the old nested Data wrapper the project
// list decoded empty and every remote machine command failed with "project not
// found". Uses the real sendSuccess envelope shape.
func TestResolveProjectContext_Remote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":7,"name":"web"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	name, id, err := resolveProjectContext("web")
	require.NoError(t, err)
	assert.Equal(t, "web", name)
	assert.Equal(t, uint(7), id)
}

// TestFetchMachineIdentities_Remote guards the same fix on the machine-identities
// list endpoint: the identities must decode from the stripped envelope, not an
// always-empty nested Data wrapper.
func TestFetchMachineIdentities_Remote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/7/machine-identities" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"machine_identities":[{"id":1,"name":"ci-runner"},{"id":2,"name":"deployer"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	ids, err := fetchMachineIdentities(context.Background(), 7)
	require.NoError(t, err)
	require.Len(t, ids, 2)
	assert.Equal(t, "ci-runner", ids[0].Name)
	assert.Equal(t, "deployer", ids[1].Name)
}
