// schedule_success_test.go — exercises the setScheduleCmd/getScheduleCmd/
// clearScheduleCmd RunE closures on the success path (schedule_rune_test.go only
// covers early error returns before any network call).
package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetScheduleCmd_Success(t *testing.T) {
	_, done := scheduleStub(t)
	defer done()

	schedDays = "mon,fri"
	schedStartHour = 9
	schedEndHour = 17
	schedTimezone = ""

	out := captureStdoutForFolder(t, func() {
		err := setScheduleCmd.RunE(setScheduleCmd, []string{"42"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Schedule set")
}

func TestSetScheduleCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	schedDays = "mon,fri"
	schedStartHour = 9
	schedEndHour = 17
	err := setScheduleCmd.RunE(setScheduleCmd, []string{"42"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSetScheduleCmd_APIError(t *testing.T) {
	_, done := scheduleStub(t)
	defer done()

	schedDays = "mon,fri"
	schedStartHour = 9
	schedEndHour = 17
	err := setScheduleCmd.RunE(setScheduleCmd, []string{"999"})
	require.Error(t, err)
}

func TestGetScheduleCmd_Success(t *testing.T) {
	_, done := scheduleStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := getScheduleCmd.RunE(getScheduleCmd, []string{"42"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "schedule:")
	assert.Contains(t, out, "UTC")
}

func TestGetScheduleCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := getScheduleCmd.RunE(getScheduleCmd, []string{"42"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestGetScheduleCmd_APIError(t *testing.T) {
	_, done := scheduleStub(t)
	defer done()
	err := getScheduleCmd.RunE(getScheduleCmd, []string{"999"})
	require.Error(t, err)
}

func TestClearScheduleCmd_Success(t *testing.T) {
	_, done := scheduleStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := clearScheduleCmd.RunE(clearScheduleCmd, []string{"42"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Schedule cleared")
}

func TestClearScheduleCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := clearScheduleCmd.RunE(clearScheduleCmd, []string{"42"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestClearScheduleCmd_APIError(t *testing.T) {
	_, done := scheduleStub(t)
	defer done()
	err := clearScheduleCmd.RunE(clearScheduleCmd, []string{"999"})
	require.Error(t, err)
}
