package anomalies

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeConfigServer(t *testing.T, current anomalyConfigRecord) (*httptest.Server, *http.Request) {
	t.Helper()
	var lastReq *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReq = r
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"config": current,
			},
		}
		if r.Method == http.MethodPut {
			var body anomalyConfigRecord
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			resp = map[string]interface{}{
				"data": map[string]interface{}{
					"config": body,
				},
			}
		}
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, lastReq
}

// TestAnomalyConfigGet_Remote verifies that "anomaly config get" issues a GET
// to /api/v1/admin/anomaly-config and decodes the response.
func TestAnomalyConfigGet_Remote(t *testing.T) {
	cfg := anomalyConfigRecord{
		LookbackDays:    7,
		QuarantineHours: 24,
		MLEnabled:       false,
		MLThreshold:     0.6,
		MLNumTrees:      100,
		MLSampleSize:    256,
	}
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		resp := map[string]interface{}{
			"data": map[string]interface{}{"config": cfg},
		}
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runConfigGetRemote(rc))
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Equal(t, anomalyConfigPath, gotPath)
}

// TestAnomalyConfigSet_Remote_PartialUpdate verifies that only explicitly
// changed flags are reflected in the PUT body; unchanged fields keep their
// current values from the GET.
func TestAnomalyConfigSet_Remote_PartialUpdate(t *testing.T) {
	// Server starts with these values.
	initial := anomalyConfigRecord{
		LookbackDays:    7,
		QuarantineHours: 24,
		MLEnabled:       false,
		MLThreshold:     0.6,
		MLNumTrees:      100,
		MLSampleSize:    256,
	}

	var putBody anomalyConfigRecord
	var gotMethod string
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			gotMethod = r.Method
			resp := map[string]interface{}{
				"data": map[string]interface{}{"config": initial},
			}
			b, _ := json.Marshal(resp)
			_, _ = w.Write(b)
			return
		}
		// PUT — capture body
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &putBody)
		resp := map[string]interface{}{
			"data": map[string]interface{}{"config": putBody},
		}
		rb, _ := json.Marshal(resp)
		_, _ = w.Write(rb)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	// Build a cobra command with only --ml-enabled set.
	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&cfgMLEnabled, "ml-enabled", false, "")
	require.NoError(t, cmd.Flags().Set("ml-enabled", "true"))

	require.NoError(t, runConfigSetRemote(rc, cmd))

	// Should have done GET then PUT.
	assert.Equal(t, http.MethodPut, gotMethod)
	// Only ml_enabled changed; everything else is from the initial config.
	assert.True(t, putBody.MLEnabled, "ml_enabled must be true after --ml-enabled flag")
	assert.Equal(t, initial.LookbackDays, putBody.LookbackDays, "lookback_days must be unchanged")
	assert.Equal(t, initial.QuarantineHours, putBody.QuarantineHours, "quarantine_hours must be unchanged")
	assert.InDelta(t, initial.MLThreshold, putBody.MLThreshold, 1e-9, "ml_threshold must be unchanged")
}

// TestAnomalyConfigSet_Remote_AllFlags verifies that setting all flags in one
// call produces a PUT body that reflects every change.
func TestAnomalyConfigSet_Remote_AllFlags(t *testing.T) {
	initial := anomalyConfigRecord{
		LookbackDays:    7,
		QuarantineHours: 24,
		MLEnabled:       false,
		MLThreshold:     0.6,
		MLNumTrees:      100,
		MLSampleSize:    256,
	}

	var putBody anomalyConfigRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			resp := map[string]interface{}{
				"data": map[string]interface{}{"config": initial},
			}
			b, _ := json.Marshal(resp)
			_, _ = w.Write(b)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &putBody)
		resp := map[string]interface{}{
			"data": map[string]interface{}{"config": putBody},
		}
		rb, _ := json.Marshal(resp)
		_, _ = w.Write(rb)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	// Build a cobra command with all flags set.
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

	require.NoError(t, cmd.Flags().Set("lookback-days", "30"))
	require.NoError(t, cmd.Flags().Set("quarantine-hours", "48"))
	require.NoError(t, cmd.Flags().Set("off-hours-enabled", "true"))
	require.NoError(t, cmd.Flags().Set("off-hours-timezone", "America/New_York"))
	require.NoError(t, cmd.Flags().Set("off-hours-start", "20"))
	require.NoError(t, cmd.Flags().Set("off-hours-end", "8"))
	require.NoError(t, cmd.Flags().Set("ml-enabled", "true"))
	require.NoError(t, cmd.Flags().Set("ml-threshold", "0.75"))
	require.NoError(t, cmd.Flags().Set("ml-num-trees", "200"))
	require.NoError(t, cmd.Flags().Set("ml-sample-size", "512"))

	require.NoError(t, runConfigSetRemote(rc, cmd))

	assert.Equal(t, 30, putBody.LookbackDays)
	assert.Equal(t, 48, putBody.QuarantineHours)
	assert.True(t, putBody.OffHoursEnabled)
	assert.Equal(t, "America/New_York", putBody.OffHoursTimezone)
	assert.Equal(t, 20, putBody.OffHoursStart)
	assert.Equal(t, 8, putBody.OffHoursEnd)
	assert.True(t, putBody.MLEnabled)
	assert.InDelta(t, 0.75, putBody.MLThreshold, 1e-9)
	assert.Equal(t, 200, putBody.MLNumTrees)
	assert.Equal(t, 512, putBody.MLSampleSize)
}
