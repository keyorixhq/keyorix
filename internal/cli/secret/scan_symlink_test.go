// scan_symlink_test.go — regression test for #153: `secret scan` must not follow
// symlinks. A malicious repo could commit a symlink pointing outside the scanned
// tree at a file the scanning user has read access to (e.g. ~/.aws/credentials or
// /etc/shadow); if followed, its content would be pattern-matched and written into
// the scan report, leaking the SCANNING USER's own files.
package secret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunScan_DoesNotFollowSymlinksOutOfScanRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on windows")
	}

	root := t.TempDir()
	outside := t.TempDir()

	// A regular, in-tree file: must still be found — the symlink fix must not
	// regress ordinary scanning.
	inTreeValue := strings.Repeat("A", 40)
	inTreeContent := "AWS_SECRET_ACCESS_KEY=" + inTreeValue + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "config.env"), []byte(inTreeContent), 0600))

	// A file OUTSIDE the scan root, standing in for a sensitive file the scanning
	// user can read (e.g. ~/.aws/credentials) that a malicious repo has no business
	// exposing.
	outsideValue := strings.Repeat("Z", 40)
	outsideContent := "AWS_SECRET_ACCESS_KEY=" + outsideValue + "\n"
	outsideFile := filepath.Join(outside, "credentials.env")
	require.NoError(t, os.WriteFile(outsideFile, []byte(outsideContent), 0600))

	// A symlink INSIDE the scan root pointing at the outside file — the attack
	// primitive: a malicious repo commits this symlink, and the scanning user's
	// clone+scan would otherwise transparently follow it.
	require.NoError(t, os.Symlink(outsideFile, filepath.Join(root, "linked.env")))

	reportPath := filepath.Join(t.TempDir(), "report.json")
	origReport, origSeverity, origStaged, origCommit := scanReport, scanSeverity, scanStaged, scanCommit
	scanReport, scanSeverity, scanStaged, scanCommit = reportPath, "", false, ""
	t.Cleanup(func() {
		scanReport, scanSeverity, scanStaged, scanCommit = origReport, origSeverity, origStaged, origCommit
	})

	require.NoError(t, runScan(scanCmd, []string{root}))

	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report ScanReport
	require.NoError(t, json.Unmarshal(data, &report))

	values := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		values = append(values, f.Value)
	}
	assert.Contains(t, values, inTreeValue, "a regular file inside the scan root must still be scanned")
	assert.NotContains(t, values, outsideValue, "the scanner must not follow a symlink to read a file outside the scan root")
}
