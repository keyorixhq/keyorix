package hygiene

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestPrintRollup_Clean(t *testing.T) {
	out := captureStdout(t, func() {
		printRollup(&rollup{})
	})
	assert.Contains(t, out, "No projects carry outstanding signals")
}

func TestPrintRollup_WithDebt(t *testing.T) {
	r := &rollup{
		Totals: counts{OrphanedSecrets: 2, UnusedSecrets: 5, RotationOverdue: 1},
		Projects: []projectBreakdown{
			{ProjectID: 3, ProjectName: "web", counts: counts{OrphanedSecrets: 2, UnusedSecrets: 5, RotationOverdue: 1}},
		},
	}
	out := captureStdout(t, func() { printRollup(r) })
	assert.Contains(t, out, "orphaned secrets")
	assert.Contains(t, out, "web")
}

func TestHygieneCmdFlags(t *testing.T) {
	assert.NotNil(t, HygieneCmd.Flags().Lookup("unused-days"))
	assert.NotNil(t, HygieneCmd.Flags().Lookup("expiring-days"))
	assert.NotNil(t, HygieneCmd.Flags().Lookup("stale-days"))
}
