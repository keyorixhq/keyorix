// mfa_stepup_remote_test.go — exercises the remaining branches of runMFAStepUp
// that mfa_stepup_flag_warning_test.go doesn't reach: the "no remote session"
// early-return, the interactive-prompt path when --code is omitted (both the
// empty/EOF failure and, via a stubbed remote server, the full success path).
package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetMFACodeFlag(t *testing.T) {
	t.Helper()
	_ = mfaStepUpCmd.Flags().Set("code", "")
	mfaStepUpCmd.Flags().Lookup("code").Changed = false
	t.Cleanup(func() {
		_ = mfaStepUpCmd.Flags().Set("code", "")
		mfaStepUpCmd.Flags().Lookup("code").Changed = false
	})
}

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

// TestRunMFAStepUp_NoRemoteSession exercises the "!ok" early return: with no
// KEYORIX_SERVER/KEYORIX_TOKEN, no ~/.keyorix/cli.yaml (HOME redirected to an
// empty temp dir), and no CWD-relative keyorix.yaml, NewRemoteClient must
// report no remote configuration.
func TestRunMFAStepUp_NoRemoteSession(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	resetMFACodeFlag(t)

	err := runMFAStepUp(mfaStepUpCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MFA step-up requires remote mode")
}

// TestRunMFAStepUp_Success drives the full happy path: a stubbed remote
// server accepts the POST and runMFAStepUp reports success. --code is set
// explicitly so the interactive prompt is skipped.
func TestRunMFAStepUp_Success(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	resetMFACodeFlag(t)
	require.NoError(t, mfaStepUpCmd.Flags().Set("code", "123456"))

	out := captureStdout(t, func() {
		require.NoError(t, runMFAStepUp(mfaStepUpCmd, nil))
	})

	assert.Equal(t, "/api/v1/auth/mfa/stepup", gotPath)
	assert.Contains(t, gotBody, "123456")
	assert.Contains(t, out, "MFA step-up verified")
}

// TestRunMFAStepUp_EmptyCodeFromPrompt drives the --code-omitted branch: with
// a working remote session but no --code flag, runMFAStepUp falls through to
// the interactive prompt. Redirecting stdin to an already-closed pipe makes
// fmt.Scanln fail immediately (EOF), which must surface as "code is required"
// without ever reaching the remote server.
func TestRunMFAStepUp_EmptyCodeFromPrompt(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	resetMFACodeFlag(t)

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close()) // no writer, so the reader sees immediate EOF
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	err = runMFAStepUp(mfaStepUpCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code is required")
	assert.False(t, called, "remote server should not be contacted when the code prompt fails")
}
