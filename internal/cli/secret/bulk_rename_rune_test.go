// bulk_rename_rune_test.go — exercises bulkRenameCmd.RunE directly
// (bulk_rename_remote_test.go only tests postBulkRename/parseRenamePairs).
package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetBulkRenameFlags(t *testing.T) {
	t.Helper()
	origProject, origApply, origPairs := bulkRenameProject, bulkRenameApply, bulkRenamePairs
	t.Cleanup(func() {
		bulkRenameProject = origProject
		bulkRenameApply = origApply
		bulkRenamePairs = origPairs
	})
}

func TestBulkRenameCmd_MissingProject(t *testing.T) {
	resetBulkRenameFlags(t)
	bulkRenameProject = 0
	err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestBulkRenameCmd_MissingRenames(t *testing.T) {
	resetBulkRenameFlags(t)
	bulkRenameProject = 5
	bulkRenamePairs = nil
	err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--rename")
}

func TestBulkRenameCmd_InvalidPair(t *testing.T) {
	resetBulkRenameFlags(t)
	bulkRenameProject = 5
	bulkRenamePairs = []string{"noequals"}
	err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
	require.Error(t, err)
}

func TestBulkRenameCmd_NoServer(t *testing.T) {
	resetBulkRenameFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	bulkRenameProject = 5
	bulkRenamePairs = []string{"12=NEW_NAME"}
	err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestBulkRenameCmd_Success_DryRun(t *testing.T) {
	resetBulkRenameFlags(t)
	rc, done := bulkRenameStub(t, nil)
	defer done()
	_ = rc

	bulkRenameProject = 5
	bulkRenamePairs = []string{"12=DB_PW"}
	bulkRenameApply = false

	out := captureStdoutForFolder(t, func() {
		err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Dry run")
	assert.Contains(t, out, "would be renamed")
}

func TestBulkRenameCmd_Success_Apply(t *testing.T) {
	resetBulkRenameFlags(t)
	var captured map[string]interface{}
	rc, done := bulkRenameStub(t, &captured)
	defer done()
	_ = rc

	bulkRenameProject = 5
	bulkRenamePairs = []string{"12=DB_PW"}
	bulkRenameApply = true

	captureStdoutForFolder(t, func() {
		err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
		require.NoError(t, err)
	})
	// bulkRenameStub's fixture always reports dry_run:true regardless of what was
	// sent; what matters here is that --apply sent dry_run:false in the request.
	assert.Equal(t, false, captured["dry_run"])
}

func TestBulkRenameCmd_PostError(t *testing.T) {
	resetBulkRenameFlags(t)
	rc, done := bulkRenameStub(t, nil)
	defer done()
	_ = rc

	bulkRenameProject = 999
	bulkRenamePairs = []string{"12=DB_PW"}

	err := bulkRenameCmd.RunE(bulkRenameCmd, nil)
	require.Error(t, err)
}
