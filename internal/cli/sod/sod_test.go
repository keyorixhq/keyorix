package sod

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func setupRemote(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "short", truncate("short", 26))
	assert.Equal(t, "abcde…", truncate("abcdefghij", 6))
	assert.Equal(t, "x", truncate("xyz", 1))
}

func TestPolicyList_Remote(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"policies":[],"count":0}}`))
		})
		out := captureStdout(t, func() { require.NoError(t, policyListCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "No separation-of-duties policies defined.")
	})
	t.Run("populated", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/sod/policies", r.URL.Path)
			_, _ = w.Write([]byte(`{"success":true,"data":{"count":1,"policies":[{"id":2,"name":"assign-vs-delete","permission_a":"roles.assign","permission_b":"secrets.delete"}]}}`))
		})
		out := captureStdout(t, func() { require.NoError(t, policyListCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "assign-vs-delete")
		assert.Contains(t, out, "roles.assign")
		assert.Contains(t, out, "secrets.delete")
	})
}

func TestPolicyCreate_RequiredFlagsAndRemote(t *testing.T) {
	sName, sPermA, sPermB = "", "", ""
	require.ErrorContains(t, policyCreateCmd.RunE(nil, nil), "are required")

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write([]byte(`{"success":true,"data":{"policy":{"id":5,"name":"p","permission_a":"a","permission_b":"b"}}}`))
	})
	sName, sPermA, sPermB, sDesc = "p", "roles.assign", "secrets.delete", "toxic combo"
	t.Cleanup(func() { sName, sPermA, sPermB, sDesc = "", "", "", "" })
	out := captureStdout(t, func() { require.NoError(t, policyCreateCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Created SoD policy 5")
	assert.Contains(t, out, "must not be held together")
}

func TestPolicyDelete_RequiredIDAndRemote(t *testing.T) {
	sID = 0
	require.ErrorContains(t, policyDeleteCmd.RunE(nil, nil), "--id is required")

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/sod/policies/5", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	sID = 5
	t.Cleanup(func() { sID = 0 })
	out := captureStdout(t, func() { require.NoError(t, policyDeleteCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Deleted SoD policy 5.")
}

func TestViolations_Remote(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"violations":[],"count":0}}`))
		})
		out := captureStdout(t, func() { require.NoError(t, violationsCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "No separation-of-duties violations.")
	})
	t.Run("degraded with a violation", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"count":1,"degraded":true,"degraded_reasons":["principal 9 unreadable"],"violations":[{"policy_name":"assign-vs-delete","username":"alice","email":"a@x.io","permission_a":"roles.assign","permission_b":"secrets.delete"}]}}`))
		})
		out := captureStdout(t, func() { require.NoError(t, violationsCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "DEGRADED SCAN")
		assert.Contains(t, out, "principal 9 unreadable")
		assert.Contains(t, out, "1 violation(s):")
		assert.Contains(t, out, "alice <a@x.io>")
	})
}
