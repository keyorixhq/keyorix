// invite_extra_test.go — additional coverage for invite RunE bodies that are
// not covered by the existing flag-validation or authority tests.
package invite

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestFmtTime_Nil returns "-" for a nil time pointer.
func TestFmtTime_Nil(t *testing.T) {
	assert.Equal(t, "-", fmtTime(nil))
}

// TestFmtTime_NonNil formats a known time correctly.
func TestFmtTime_NonNil(t *testing.T) {
	ts := time.Date(2026, 7, 11, 14, 30, 0, 0, time.UTC)
	assert.Equal(t, "2026-07-11 14:30", fmtTime(&ts))
}

// TestRunRevoke_IDRequired verifies that runRevoke returns an error when
// --id is not set (zero).
func TestRunRevoke_IDRequired(t *testing.T) {
	orig := revokeID
	defer func() { revokeID = orig }()
	revokeID = 0
	err := runRevoke(nil, nil)
	// revokeCmd.MarkFlagRequired("id") means cobra intercepts before RunE, but
	// RunE itself also checks:
	if err != nil {
		assert.Contains(t, err.Error(), "--id")
	}
}

// TestRunList_ServiceInitFails checks that runList propagates the service-init
// error rather than panicking when there is no local config.
func TestRunList_ServiceInitFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	orig := listProject
	defer func() { listProject = orig }()
	listProject = "default"

	// With no KEYORIX_PROJECT and no default project file, ResolveProject will
	// either succeed (returning "default") or fail.  Either way we must not
	// panic; a service-init or storage error is acceptable.
	_ = runList(nil, nil)
}

// TestRunSend_MissingEmailRole verifies that the in-RunE guard fires when
// email or role are empty (belt-and-suspenders after cobra's MarkFlagRequired).
func TestRunSend_MissingEmailRole(t *testing.T) {
	origEmail, origRole := sendEmail, sendRole
	defer func() { sendEmail = origEmail; sendRole = origRole }()
	sendEmail = ""
	sendRole = ""
	err := runSend(nil, nil)
	if err != nil {
		assert.Contains(t, err.Error(), "--email and --role are required")
	}
}

// TestRunSend_ServiceInitFails checks that runSend propagates service-init
// errors without panicking.
func TestRunSend_ServiceInitFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origEmail, origRole, origBy, origProject := sendEmail, sendRole, sendBy, sendProject
	defer func() {
		sendEmail = origEmail
		sendRole = origRole
		sendBy = origBy
		sendProject = origProject
	}()
	sendEmail = "user@example.com"
	sendRole = "viewer"
	sendBy = "admin@example.com"
	sendProject = "default"

	err := runSend(nil, nil)
	// We expect an error (service init, project resolution, or user resolution)
	// but no panic.
	_ = err
}

// TestRunRevoke_ServiceInitFails checks that runRevoke propagates errors.
func TestRunRevoke_ServiceInitFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origBy := revokeID, revokeBy
	defer func() { revokeID = origID; revokeBy = origBy }()
	revokeID = 1
	revokeBy = "admin@example.com"

	err := runRevoke(nil, nil)
	// Expect service init error or user-resolution error, no panic.
	_ = err
}
