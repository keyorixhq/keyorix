package auditverify

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckVerifyStateHead_RetentionAnchorBoundary pins the one exemption of
// the head-gone rule, as internal/core's auditVerifyStateHeadGone: a missing
// certified head row is excused only when the authenticated retention anchor's
// RowID is strictly above it. The real write path cannot drive this (the pin
// names a row written at checkpoint time, never old enough to be purged), so
// it is checked here directly.
func TestCheckVerifyStateHead_RetentionAnchorBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	seedEmptySchema(t, path)
	db, err := OpenSQLiteReadOnly(path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var row verifyStateRow
	row.Pin = &struct {
		HeadID   uint64 `json:"head_id"`
		HeadHash string `json:"head_hash"`
	}{HeadID: 5, HeadHash: "certified"}

	for _, tc := range []struct {
		anchorRowID uint64
		want        Verdict
	}{
		{0, VerdictBroken}, // no authenticated anchor
		{5, VerdictBroken}, // the anchor's row is the first surviving one: #5 must exist
		{6, VerdictValid},  // a sanctioned purge removed #5
	} {
		result := &Result{Verdict: VerdictValid, retentionAnchorRowID: tc.anchorRowID}
		require.NoError(t, checkVerifyStateHead(context.Background(), db, &row, result))
		assert.Equal(t, tc.want, result.Verdict, "anchor RowID %d: %s", tc.anchorRowID, result.Reason)
	}
}
