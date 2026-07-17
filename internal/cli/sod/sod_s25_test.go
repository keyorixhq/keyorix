package sod

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyList_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	err := policyListCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestPolicyCreate_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	sName, sPermA, sPermB = "p", "a", "b"
	t.Cleanup(func() { sName, sPermA, sPermB = "", "", "" })
	err := policyCreateCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestPolicyDelete_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	sID = 7
	t.Cleanup(func() { sID = 0 })
	err := policyDeleteCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestViolations_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	err := violationsCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestViolations_NoEmail(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"count":1,"violations":[{"policy_name":"p","username":"bob","email":"","permission_a":"a","permission_b":"b"}]}}`))
	})
	out := captureStdout(t, func() { require.NoError(t, violationsCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "1 violation(s):")
	assert.Contains(t, out, "bob")
	assert.NotContains(t, out, "<")
}
