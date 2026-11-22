package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyAuditChain_ModifiedRowReasonIsPlainWords: the reason an operator reads for
// a row edited after it was written says what happened in plain words and carries no
// internal reference (an issue number, a design section, an encoding name). The event
// id travels in FirstBrokenID, as before. Only the text changes: verdict and id are
// the same.
func TestVerifyAuditChain_ModifiedRowReasonIsPlainWords(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	appendEvent(t, ls, "secret.read", "first", base)
	e2 := appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))
	appendEvent(t, ls, "secret.read", "third", base.Add(2*time.Second))

	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("id = ?", e2.ID).
		Update("description", "second (quietly edited)").Error)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, v.Valid)
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, e2.ID, *v.FirstBrokenID)

	assert.Contains(t, v.Reason, "the recorded entry_hash does not match this row's contents")
	assert.Contains(t, v.Reason, "the row was changed after it was written")
	assert.NotRegexp(t, `#[0-9]{3,}`, v.Reason)
	for _, internal := range []string{"design §", "ADR-", "pre-#", "§", "matches neither"} {
		assert.NotContains(t, v.Reason, internal)
	}
}

// TestVerifyAuditChain_UnmigratedRowReasonIsPlainWords: the reason for a row still
// hashed in the old format (an upgrade step not run, not tampering) names the old
// format in plain words and carries no issue number. Verdict, id and the migrate
// endpoint it points to are unchanged.
func TestVerifyAuditChain_UnmigratedRowReasonIsPlainWords(t *testing.T) {
	ls := newAuditChainTestStore(t)
	e1 := appendLegacyEncodedEvent(t, ls, "first", time.Now().UTC(), auditGenesisHash)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, v.Valid)
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, e1.ID, *v.FirstBrokenID)

	assert.Contains(t, v.Reason, "old audit-hash format")
	assert.Contains(t, v.Reason, "NOT evidence of tampering")
	assert.Contains(t, v.Reason, "/api/v1/audit/migrate-chain-encoding")
	assert.NotRegexp(t, `#[0-9]{3,}`, v.Reason)
	for _, internal := range []string{"design §", "ADR-", "pre-#", "§", "matches neither"} {
		assert.NotContains(t, v.Reason, internal)
	}
}
