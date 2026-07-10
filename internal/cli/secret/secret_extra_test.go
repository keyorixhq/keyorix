package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyCmd_IDRequired(t *testing.T) {
	orig := classifyID
	defer func() { classifyID = orig }()
	classifyID = 0
	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestClassifyCmd_BadLevel(t *testing.T) {
	origID, origL := classifyID, classifyLevel
	defer func() { classifyID = origID; classifyLevel = origL }()
	classifyID = 1
	classifyLevel = "top-secret"
	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--level must be")
}

func TestClassifyCmd_ValidLevels(t *testing.T) {
	origID, origL := classifyID, classifyLevel
	defer func() { classifyID = origID; classifyLevel = origL }()
	classifyID = 1
	// Valid levels pass the check but fail on network (not connected).
	for _, level := range []string{"", "public", "internal", "confidential", "restricted"} {
		classifyLevel = level
		err := classifyCmd.RunE(classifyCmd, nil)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "--level must be", "level=%q should be valid", level)
	}
}

func TestCopyCmd_BothIDsRequired(t *testing.T) {
	origID, origEnv := copyID, copyToEnv
	defer func() { copyID = origID; copyToEnv = origEnv }()
	copyID = 0
	copyToEnv = 0
	err := copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id and --to-environment are required")

	copyID = 5
	copyToEnv = 0
	err = copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)

	copyID = 0
	copyToEnv = 2
	err = copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)
}

func TestSuspendCmd_IDRequired(t *testing.T) {
	orig := suspendID
	defer func() { suspendID = orig }()
	suspendID = 0
	err := suspendCmd.RunE(suspendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestResumeCmd_IDRequired(t *testing.T) {
	orig := resumeID
	defer func() { resumeID = orig }()
	resumeID = 0
	err := resumeCmd.RunE(resumeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestAutoRotateCmd_IDRequired(t *testing.T) {
	orig := autoRotateID
	defer func() { autoRotateID = orig }()
	autoRotateID = 0
	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestAutoRotateCmd_BadCharset(t *testing.T) {
	origID, origC := autoRotateID, autoRotateCharset
	defer func() { autoRotateID = origID; autoRotateCharset = origC }()
	autoRotateID = 1
	autoRotateCharset = "emoji"
	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--charset must be")
}

func TestAutoRotateCmd_BackendWithoutRef(t *testing.T) {
	// The backend/ref check happens after NewRemoteClient, so wire a stub server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origC, origB, origR := autoRotateID, autoRotateCharset, autoRotateBackend, autoRotateRef
	defer func() {
		autoRotateID = origID
		autoRotateCharset = origC
		autoRotateBackend = origB
		autoRotateRef = origR
	}()
	autoRotateID = 1
	autoRotateCharset = ""
	autoRotateBackend = "aws"
	autoRotateRef = ""
	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--backend and --ref must be set together")
}

func TestDescriptionCmd_IDRequired(t *testing.T) {
	orig := descID
	defer func() { descID = orig }()
	descID = 0
	err := descriptionCmd.RunE(descriptionCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestSecretCmdHasExpectedSubcommands(t *testing.T) {
	names := make(map[string]bool)
	for _, c := range SecretCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{
		"create", "get", "list", "update", "delete", "versions",
		"classify", "copy", "suspend", "resume", "auto-rotate", "description",
	} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}
