// schedule_rune_test.go — tests for schedule command RunE error branches.
//
// These tests exercise code paths that fail before any network call is made
// (parseSecretArg errors, convertDayNames errors, and missing-server errors).
// They do NOT start an httptest.Server.
package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetScheduleCmd_InvalidSecretArg verifies that RunE returns an error when
// the secret argument cannot be parsed as a positive integer.
// parseSecretArg is the FIRST thing called in RunE, before scheduleClient.
func TestSetScheduleCmd_InvalidSecretArg(t *testing.T) {
	schedDays = "1,2,3,4,5"
	schedStartHour = 9
	schedEndHour = 17
	schedTimezone = "UTC"

	err := setScheduleCmd.RunE(setScheduleCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret id")
}

// TestSetScheduleCmd_InvalidDays verifies that RunE returns an error when the
// days value is unrecognised.
// convertDayNames is called BEFORE scheduleClient in the RunE chain.
func TestSetScheduleCmd_InvalidDays(t *testing.T) {
	schedDays = "invalid-day"
	schedStartHour = 9
	schedEndHour = 17
	schedTimezone = "UTC"

	err := setScheduleCmd.RunE(setScheduleCmd, []string{"42"})
	require.Error(t, err)
	// convertDayNames returns "invalid day" error; no server needed.
	assert.Contains(t, err.Error(), "invalid day")
}

// TestGetScheduleCmd_InvalidSecretArg verifies that RunE returns an error when
// the secret argument cannot be parsed.
func TestGetScheduleCmd_InvalidSecretArg(t *testing.T) {
	err := getScheduleCmd.RunE(getScheduleCmd, []string{"0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret id")
}

// TestClearScheduleCmd_InvalidSecretArg verifies that RunE returns an error when
// the secret argument cannot be parsed.
func TestClearScheduleCmd_InvalidSecretArg(t *testing.T) {
	err := clearScheduleCmd.RunE(clearScheduleCmd, []string{"xyz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret id")
}

// TestScheduleClient_NoServer verifies that scheduleClient returns an error
// when KEYORIX_SERVER is not configured.
func TestScheduleClient_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, err := scheduleClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
