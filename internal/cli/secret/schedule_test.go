package secret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scheduleStub sets up an httptest server that stubs the /schedule routes.
func scheduleStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	sched := models.SecretAccessSchedule{
		ID:           1,
		SecretNodeID: 42,
		AllowedDays:  "1,2,3,4,5",
		StartHour:    9,
		EndHour:      17,
		Timezone:     "UTC",
	}
	schedJSON, _ := json.Marshal(sched)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/42/schedule":
			_, _ = w.Write([]byte(`{"success":true,"data":` + string(schedJSON) + `}`))

		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/42/schedule":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			// Echo back what was sent, merged with our fixture IDs.
			resp := map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"id":             1,
					"secret_node_id": 42,
					"allowed_days":   body["allowed_days"],
					"start_hour":     body["start_hour"],
					"end_hour":       body["end_hour"],
					"timezone":       body["timezone"],
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/secrets/42/schedule":
			_, _ = w.Write([]byte(`{"success":true,"data":{"deleted":true}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// TestSetSecretSchedule_Remote verifies PUT /api/v1/secrets/{id}/schedule.
func TestSetSecretSchedule_Remote(t *testing.T) {
	rc, done := scheduleStub(t)
	defer done()

	var out models.SecretAccessSchedule
	err := rc.Put(context.Background(), "/api/v1/secrets/42/schedule", map[string]interface{}{
		"allowed_days": "1,2,3,4,5",
		"start_hour":   9,
		"end_hour":     17,
		"timezone":     "UTC",
	}, &out)
	require.NoError(t, err)
	assert.Equal(t, "1,2,3,4,5", out.AllowedDays)
	assert.Equal(t, 9, out.StartHour)
	assert.Equal(t, 17, out.EndHour)
	assert.Equal(t, "UTC", out.Timezone)
}

// TestGetSecretSchedule_Remote verifies GET /api/v1/secrets/{id}/schedule.
func TestGetSecretSchedule_Remote(t *testing.T) {
	rc, done := scheduleStub(t)
	defer done()

	var out models.SecretAccessSchedule
	err := rc.Get(context.Background(), "/api/v1/secrets/42/schedule", &out)
	require.NoError(t, err)
	assert.Equal(t, uint(42), out.SecretNodeID)
	assert.Equal(t, "1,2,3,4,5", out.AllowedDays)
	assert.Equal(t, 9, out.StartHour)
	assert.Equal(t, 17, out.EndHour)
}

// TestClearSecretSchedule_Remote verifies DELETE /api/v1/secrets/{id}/schedule.
func TestClearSecretSchedule_Remote(t *testing.T) {
	rc, done := scheduleStub(t)
	defer done()

	err := rc.Delete(context.Background(), "/api/v1/secrets/42/schedule")
	require.NoError(t, err)
}

// TestDayNameConversion covers the convertDayNames helper.
func TestDayNameConversion(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"mon,fri", "1,5", false},
		{"mon,tue,wed,thu,fri", "1,2,3,4,5", false},
		{"1,2,3", "1,2,3", false},
		{"*", "*", false},
		{"sun", "7", false},
		{"sat,sun", "6,7", false},
		{"0", "", true},   // 0 is not a valid ISO weekday
		{"8", "", true},   // 8 is out of range
		{"abc", "", true}, // unrecognised name
	}
	for _, tc := range tests {
		got, err := convertDayNames(tc.input)
		if tc.wantErr {
			assert.Error(t, err, "input=%q", tc.input)
		} else {
			require.NoError(t, err, "input=%q", tc.input)
			assert.Equal(t, tc.want, got, "input=%q", tc.input)
		}
	}
}
