package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The summary row (#3456) lists at most shareListElevationDetailCap elevations and
// says when it cut the list; Count is always the full number, and the payload stays
// valid JSON under the audit Diff cap.
func TestListUserShareViews_SummaryRowIsBounded(t *testing.T) {
	n := shareListElevationDetailCap + 3
	sw := newShareListAuditWorld(t, n)
	before := sbAuditHighWater(t, sw.w.db)
	_, err := sw.w.core.ListUserShareViews(context.Background(), sw.recipient)
	require.NoError(t, err)
	rows := sw.elevationRows(t, before)
	require.Len(t, rows, 1)
	assert.Less(t, len(rows[0].Diff), auditDiffMaxLen)
	var d shareListElevationDetail
	require.NoError(t, json.Unmarshal([]byte(rows[0].Diff), &d), rows[0].Diff)
	assert.Equal(t, shareListElevationAction, d.Action)
	assert.Equal(t, n, d.Count)
	assert.True(t, d.Truncated)
	assert.Len(t, d.Elevations, shareListElevationDetailCap)
}
