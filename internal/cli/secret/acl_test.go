// acl_test.go — CLI tests for `keyorix secret acl list/grant/revoke` (RBAC Phase 3).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func aclRemoteStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func TestAclClient_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	_, err := aclClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAclClient_WithServer(t *testing.T) {
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {})
	defer done()
	c, err := aclClient()
	require.NoError(t, err)
	require.NotNil(t, c)
}

// ── acl list ──────────────────────────────────────────────────────────────────

func TestAclListCmd_Success_Empty(t *testing.T) {
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/secrets/7/acl", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := aclListCmd.RunE(aclListCmd, []string{"7"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No ACL grants")
}

func TestAclListCmd_Success_WithEntries(t *testing.T) {
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":1,"secret_id":7,"user_id":3,"permissions":["secrets.read","secrets.write"],"granted_by":1}]}`))
	})
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := aclListCmd.RunE(aclListCmd, []string{"7"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "secrets.read,secrets.write")
}

func TestAclListCmd_InvalidSecretArg(t *testing.T) {
	err := aclListCmd.RunE(aclListCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret id")
}

func TestAclListCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := aclListCmd.RunE(aclListCmd, []string{"7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAclListCmd_APIError(t *testing.T) {
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	err := aclListCmd.RunE(aclListCmd, []string{"7"})
	require.Error(t, err)
}

// ── acl grant ─────────────────────────────────────────────────────────────────

func resetAclGrantFlags(t *testing.T) {
	t.Helper()
	origUser, origPerms := aclGrantUser, aclGrantPerms
	t.Cleanup(func() { aclGrantUser = origUser; aclGrantPerms = origPerms })
}

func TestAclGrantCmd_MissingSecret(t *testing.T) {
	require.NoError(t, aclGrantCmd.Flags().Set("secret", "0"))
	err := aclGrantCmd.RunE(aclGrantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--secret")
}

func TestAclGrantCmd_MissingUser(t *testing.T) {
	resetAclGrantFlags(t)
	require.NoError(t, aclGrantCmd.Flags().Set("secret", "7"))
	t.Cleanup(func() { _ = aclGrantCmd.Flags().Set("secret", "0") })
	aclGrantUser = 0
	err := aclGrantCmd.RunE(aclGrantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--user")
}

func TestAclGrantCmd_MissingPerm(t *testing.T) {
	resetAclGrantFlags(t)
	require.NoError(t, aclGrantCmd.Flags().Set("secret", "7"))
	t.Cleanup(func() { _ = aclGrantCmd.Flags().Set("secret", "0") })
	aclGrantUser = 3
	aclGrantPerms = nil
	err := aclGrantCmd.RunE(aclGrantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--perm")
}

func TestAclGrantCmd_NoServer(t *testing.T) {
	resetAclGrantFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, aclGrantCmd.Flags().Set("secret", "7"))
	t.Cleanup(func() { _ = aclGrantCmd.Flags().Set("secret", "0") })
	aclGrantUser = 3
	aclGrantPerms = []string{"secrets.read"}
	err := aclGrantCmd.RunE(aclGrantCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAclGrantCmd_Success(t *testing.T) {
	resetAclGrantFlags(t)
	var capturedBody map[string]interface{}
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/secrets/7/acl", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"created":true}}`))
		_ = capturedBody
	})
	defer done()

	require.NoError(t, aclGrantCmd.Flags().Set("secret", "7"))
	t.Cleanup(func() { _ = aclGrantCmd.Flags().Set("secret", "0") })
	aclGrantUser = 3
	aclGrantPerms = []string{"secrets.read"}

	out := captureStdoutForFolder(t, func() {
		err := aclGrantCmd.RunE(aclGrantCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "ACL granted")
}

func TestAclGrantCmd_APIError(t *testing.T) {
	resetAclGrantFlags(t)
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()

	require.NoError(t, aclGrantCmd.Flags().Set("secret", "7"))
	t.Cleanup(func() { _ = aclGrantCmd.Flags().Set("secret", "0") })
	aclGrantUser = 3
	aclGrantPerms = []string{"secrets.read"}

	err := aclGrantCmd.RunE(aclGrantCmd, nil)
	require.Error(t, err)
}

// ── acl revoke ────────────────────────────────────────────────────────────────

func TestAclRevokeCmd_MissingSecret(t *testing.T) {
	require.NoError(t, aclRevokeCmd.Flags().Set("secret", "0"))
	err := aclRevokeCmd.RunE(aclRevokeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--secret")
}

func TestAclRevokeCmd_MissingAcl(t *testing.T) {
	require.NoError(t, aclRevokeCmd.Flags().Set("secret", "7"))
	require.NoError(t, aclRevokeCmd.Flags().Set("acl", "0"))
	t.Cleanup(func() { _ = aclRevokeCmd.Flags().Set("secret", "0") })
	err := aclRevokeCmd.RunE(aclRevokeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--acl")
}

func TestAclRevokeCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, aclRevokeCmd.Flags().Set("secret", "7"))
	require.NoError(t, aclRevokeCmd.Flags().Set("acl", "5"))
	t.Cleanup(func() {
		_ = aclRevokeCmd.Flags().Set("secret", "0")
		_ = aclRevokeCmd.Flags().Set("acl", "0")
	})
	err := aclRevokeCmd.RunE(aclRevokeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAclRevokeCmd_Success(t *testing.T) {
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/api/v1/secrets/7/acl/5", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	defer done()

	require.NoError(t, aclRevokeCmd.Flags().Set("secret", "7"))
	require.NoError(t, aclRevokeCmd.Flags().Set("acl", "5"))
	t.Cleanup(func() {
		_ = aclRevokeCmd.Flags().Set("secret", "0")
		_ = aclRevokeCmd.Flags().Set("acl", "0")
	})

	out := captureStdoutForFolder(t, func() {
		err := aclRevokeCmd.RunE(aclRevokeCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "ACL 5 revoked")
}

func TestAclRevokeCmd_APIError(t *testing.T) {
	done := aclRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()

	require.NoError(t, aclRevokeCmd.Flags().Set("secret", "7"))
	require.NoError(t, aclRevokeCmd.Flags().Set("acl", "5"))
	t.Cleanup(func() {
		_ = aclRevokeCmd.Flags().Set("secret", "0")
		_ = aclRevokeCmd.Flags().Set("acl", "0")
	})

	err := aclRevokeCmd.RunE(aclRevokeCmd, nil)
	require.Error(t, err)
}
