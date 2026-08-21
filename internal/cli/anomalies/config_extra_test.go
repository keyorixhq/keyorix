package anomalies

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunConfigGet_NotConnected exercises the top-level runConfigGet's
// not-connected branch, which runConfigGetRemote (tested elsewhere via the
// *_test.go stubs) never reaches on its own.
func TestRunConfigGet_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runConfigGet(configGetCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestRunConfigGet_Connected exercises the top-level runConfigGet's success
// path, which requires NewRemoteClient to return ok=true.
func TestRunConfigGet_Connected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"config":{"lookback_days":7,"quarantine_hours":24}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	require.NoError(t, runConfigGet(configGetCmd, nil))
}

// TestRunConfigGetRemote_ServerError exercises the error-return branch of
// runConfigGetRemote, left uncovered by the existing success-only test.
func TestRunConfigGetRemote_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := runConfigGetRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestRunConfigSet_NotConnected exercises the top-level runConfigSet's
// not-connected branch.
func TestRunConfigSet_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runConfigSet(configSetCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestRunConfigSet_Connected exercises the top-level runConfigSet's success
// path (RunE -> NewRemoteClient ok -> runConfigSetRemote) using the real
// configSetCmd and its registered flags, which the existing tests only drive
// through runConfigSetRemote with hand-built cobra.Command instances.
func TestRunConfigSet_Connected(t *testing.T) {
	var putBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"data":{"config":{"lookback_days":7,"quarantine_hours":24,"ml_threshold":0.6,"ml_num_trees":100,"ml_sample_size":256}}}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &putBody)
		_, _ = w.Write([]byte(`{"data":{"config":{"lookback_days":30,"quarantine_hours":24,"ml_threshold":0.6,"ml_num_trees":100,"ml_sample_size":256}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	lookbackFlag := configSetCmd.Flags().Lookup("lookback-days")
	require.NotNil(t, lookbackFlag)
	require.NoError(t, configSetCmd.Flags().Set("lookback-days", "30"))
	defer func() { lookbackFlag.Changed = false }()

	require.NoError(t, runConfigSet(configSetCmd, nil))
	assert.EqualValues(t, 30, putBody["lookback_days"])
}

// TestRunConfigSetRemote_FetchError exercises the "fetch current config"
// error-wrapping branch of runConfigSetRemote.
func TestRunConfigSetRemote_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	cmd := newEmptyConfigSetCmd()

	err := runConfigSetRemote(rc, cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch current config")
}

// TestRunConfigSetRemote_PutError exercises the PUT error-return branch of
// runConfigSetRemote (the fetch succeeds, but the write fails).
func TestRunConfigSetRemote_PutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"data":{"config":{"lookback_days":7}}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	cmd := newEmptyConfigSetCmd()

	err := runConfigSetRemote(rc, cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

// TestPrintAnomalyConfig_WithUpdatedBy covers the branch of printAnomalyConfig
// that prints the "Last updated by" line, which every other test in this
// package leaves unset (empty UpdatedBy).
func TestPrintAnomalyConfig_WithUpdatedBy(t *testing.T) {
	cfg := anomalyConfigRecord{
		LookbackDays: 7,
		UpdatedBy:    "alice",
		UpdatedAt:    "2026-08-01T00:00:00Z",
	}

	out := captureStdoutHelper(t, func() { printAnomalyConfig(cfg) })
	assert.Contains(t, out, "Last updated by:   alice at 2026-08-01T00:00:00Z")
}

// TestRunConfigSetRemote_MarshalError exercises the "marshal config" error
// branch of runConfigSetRemote. encoding/json refuses to marshal a NaN
// float64 ("json: unsupported value: NaN"), and pflag's Float64Var accepts
// the literal "NaN" without a parse error, so a caller passing
// --ml-threshold=NaN reaches json.Marshal(current) with an unsupported
// value and the call must surface that as a wrapped "marshal config" error
// rather than panicking or silently dropping the field.
func TestRunConfigSetRemote_MarshalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"config":{"lookback_days":7}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	cmd := &cobra.Command{}
	cmd.Flags().Float64Var(&cfgMLThreshold, "ml-threshold", 0, "")
	require.NoError(t, cmd.Flags().Set("ml-threshold", "NaN"))
	defer func() { cfgMLThreshold = 0 }()

	err := runConfigSetRemote(rc, cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal config")
}

// newEmptyConfigSetCmd builds a fresh cobra.Command with all the "config set"
// flags registered but none of them marked Changed, so runConfigSetRemote
// applies no overrides on top of whatever the GET returns.
func newEmptyConfigSetCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().IntVar(&cfgLookbackDays, "lookback-days", 0, "")
	cmd.Flags().IntVar(&cfgQuarantineHours, "quarantine-hours", 0, "")
	cmd.Flags().BoolVar(&cfgOffHoursEnabled, "off-hours-enabled", false, "")
	cmd.Flags().StringVar(&cfgOffHoursTimezone, "off-hours-timezone", "", "")
	cmd.Flags().IntVar(&cfgOffHoursStart, "off-hours-start", 0, "")
	cmd.Flags().IntVar(&cfgOffHoursEnd, "off-hours-end", 0, "")
	cmd.Flags().BoolVar(&cfgMLEnabled, "ml-enabled", false, "")
	cmd.Flags().Float64Var(&cfgMLThreshold, "ml-threshold", 0, "")
	cmd.Flags().IntVar(&cfgMLNumTrees, "ml-num-trees", 0, "")
	cmd.Flags().IntVar(&cfgMLSampleSize, "ml-sample-size", 0, "")
	return cmd
}

// captureStdoutHelper runs fn with os.Stdout redirected and returns what was
// written, mirroring captureStdout in terminal_injection_test.go but for a
// function with no error return.
func captureStdoutHelper(t *testing.T, fn func()) string {
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
