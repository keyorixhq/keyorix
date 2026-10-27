package auditverify_test

// MUTANT-SEC-3: the "pending" key-transition path (a record was prepared under
// the current key but the new key has not written its first checkpoint yet).
// Fixtures come from the real internal/core code path, like the other
// key-transition tests in this package.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

func TestKeyTransition_PendingSingleRecordValidUnderTheCurrentKey(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, 0)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey2, "v2"))

	r := f.verifyWith(fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.True(t, r.KeyTransition.Present)
	assert.True(t, r.KeyTransition.Authenticated)
	assert.Equal(t, 1, r.KeyTransition.Records)
}

func TestKeyTransition_PendingRecordOldKeyMACForgedBroken(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, 0)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey2, "v2"))

	parts := strings.Split(f.transitionsValue(), "\x1f")
	require.Len(t, parts, 4)
	parts[2] = strings.Repeat("ab", 32)
	f.setTransitionsValue(strings.Join(parts, "\x1f"))

	r := f.verifyWith(fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "pending key transition")
	assert.Contains(t, r.Reason, "old-key signature")
}

// v1 -> v2 completed, v2 -> v3 prepared: the previous (completed) record's
// new-key MAC is still checked under the current key.
func TestKeyTransition_PendingSecondRecordChecksTheCompletedOne(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey3, "v3"))

	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.Equal(t, 2, r.KeyTransition.Records)
	assert.True(t, r.KeyTransition.Authenticated)

	// Forge the completed record's new-key MAC (the last field of the first line).
	lines := strings.Split(f.transitionsValue(), "\n")
	require.Len(t, lines, 2)
	first := strings.Split(lines[0], "\x1f")
	require.Len(t, first, 4)
	first[3] = strings.Repeat("0", 64)
	lines[0] = strings.Join(first, "\x1f")
	f.setTransitionsValue(strings.Join(lines, "\n"))

	r = f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "new-key signature")
}
