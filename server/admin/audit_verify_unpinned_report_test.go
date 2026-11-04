package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// `admin verify-audit` names a seal's unpinned spans (AUDIT-HIGHWATER-CAS-1
// item 3, an AUDIT-SEAL-TAILS-3 leftover): the surviving rows before a gap that
// no signed artifact pinned when the loss was accepted. Before, they appeared
// only in the seal record and the accept-loss plan. The JSON report carries
// them as an added "unpinned" field on each seal; nothing else changes.
func TestVerifyAuditReport_PrintsUnpinnedSpans(t *testing.T) {
	resetAcceptLossFlags(t)
	cfg, st, _, dbPath := acceptLossFixture(t)
	ctx := context.Background()
	acceptLossFlags(5)
	acceptLossConfirm = true
	req, err := acceptLossRequest()
	require.NoError(t, err)
	require.NoError(t, acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req))

	db, err := auditverify.OpenSQLiteReadOnly(dbPath)
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	r, err := auditverify.Verify(ctx, db, auditverify.Options{CheckpointKey: acceptLossTestKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)
	require.Len(t, r.Seal.Seals, 1)
	// The fixture's one checkpoint pins only its head (#10): rows 1-3 before
	// the gap at #4 are pinned by nothing.
	require.Equal(t, []auditverify.SealSpan{{FromID: 1, ThroughID: 3}}, r.Seal.Seals[0].Unpinned,
		"the offline verifier reads the spans the seal recorded")

	prevJSON := verifyAuditJSON
	t.Cleanup(func() { verifyAuditJSON = prevJSON })

	verifyAuditJSON = false
	text, err := captureStdout(t, func() error { printVerifyAuditReport(r); return nil })
	require.NoError(t, err)
	assert.Contains(t, text, "seal #1 at ")
	assert.Contains(t, text, "    gap after #3, resuming at #5\n")
	assert.Contains(t, text, "    unpinned: audit events #1 through #3 were pinned by no signed checkpoint, mark, anchor or state when the loss was accepted; a rewrite of them before the acceptance cannot be excluded\n")

	verifyAuditJSON = true
	out, err := captureStdout(t, func() error { printVerifyAuditReport(r); return nil })
	require.NoError(t, err)
	var doc struct {
		Seal struct {
			Seals []map[string]json.RawMessage `json:"seals"`
		} `json:"seal"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), out)
	require.Len(t, doc.Seal.Seals, 1)
	seal := doc.Seal.Seals[0]
	assert.JSONEq(t, `[{"from_id":1,"through_id":3}]`, string(seal["unpinned"]))
	for _, k := range []string{"seq", "at", "operator", "reason", "evidence", "gaps", "lost_events", "digest"} {
		assert.Contains(t, seal, k, fmt.Sprintf("existing JSON field %q is kept", k))
	}
}
