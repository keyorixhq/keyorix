package auditverify_test

// Offline verify-audit and the key transition records rotate-kek and
// migrate-provider write (docs/design-audit-key-transition.md, #3642). The
// fixtures are written by the real internal/core code path, so these also pin
// the byte format the independent parser reads.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var (
	ktKey2 = bytes.Repeat([]byte{0x8}, 32)
	ktKey3 = bytes.Repeat([]byte{0x9}, 32)
)

// rotated builds a certified v1 chain and rotates it to v2 the way the
// commands do: prepare on the v1 process, complete on a v2 process.
func rotated(t *testing.T) *diffFixture {
	t.Helper()
	f := newDiffFixture(t)
	f.logEvents(6, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey2, "v2"))
	c2 := core.NewKeyorixCore(f.local)
	c2.SetAuditCheckpointKey(ktKey2, "v2")
	done, err := c2.CompleteAuditKeyTransition(f.ctx)
	require.NoError(t, err)
	require.True(t, done)
	f.core = c2
	f.logEvents(2, 0)
	return f
}

func (f *diffFixture) verifyWith(key []byte, prev ...[]byte) *auditverify.Result {
	f.t.Helper()
	r, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: key, PreviousCheckpointKeys: prev})
	require.NoError(f.t, err)
	return r
}

func (f *diffFixture) transitionsValue() string {
	f.t.Helper()
	var row models.SystemMetadata
	require.NoError(f.t, f.db.Where(&models.SystemMetadata{Key: "audit_key_transitions"}).First(&row).Error)
	return row.Value
}

func (f *diffFixture) setTransitionsValue(val string) {
	f.t.Helper()
	f.exec(`UPDATE system_metadata SET value = ? WHERE key = ?`, val, "audit_key_transitions")
}

func TestKeyTransition_NormalRotationValidOffline(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.True(t, r.KeyTransition.Present)
	assert.True(t, r.KeyTransition.Authenticated)
	assert.Equal(t, 1, r.KeyTransition.Records)
	assert.Zero(t, r.KeyTransition.OldKeyVerified)
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "--previous-checkpoint-key-file")

	r = f.verifyWith(ktKey2, fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.Equal(t, 1, r.KeyTransition.OldKeyVerified, "the old-key MAC verifies under the previous key")
	assert.NotContains(t, strings.Join(r.NotProven, "\n"), "--previous-checkpoint-key-file")

	// Under the old key alone the latest (new-key) checkpoint fails, as before.
	assert.Equal(t, auditverify.VerdictBroken, f.verifyWith(fixedCheckpointKey).Verdict)
}

// The core writes exactly what the independent parser reads, and both MACs
// verify under the keys that made them.
func TestKeyTransition_FormatMatchesCore(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	recs, err := auditverify.ParseKeyTransitions(f.transitionsValue())
	require.NoError(t, err)
	require.Len(t, recs, 1)
	r := recs[0]
	assert.Equal(t, "v1", r.OldKID)
	assert.Equal(t, "v2", r.NewKID)
	assert.True(t, r.NewMACValid(ktKey2))
	assert.True(t, r.OldMACValid(fixedCheckpointKey))
	assert.False(t, r.NewMACValid(fixedCheckpointKey), "the MACs are not interchangeable")
	assert.False(t, r.OldMACValid(ktKey2))
}

func TestKeyTransition_RecordMissingBrokenOffline(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	f.exec(`DELETE FROM system_metadata WHERE key = ?`, "audit_key_transitions")
	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "record is missing")
}

func TestKeyTransition_RecordForgedBrokenOffline(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	val := f.transitionsValue()
	flip := byte('0')
	if val[len(val)-1] == '0' {
		flip = '1'
	}
	f.setTransitionsValue(val[:len(val)-1] + string(flip))
	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "new-key signature")
}

// A holder of the new key alone rewrites the record (here: claims a larger
// pre-rotation head count) and re-signs its new-key MAC; it cannot make the
// old-key MAC. With only the new key that is undetectable offline (stated in
// NotProven); with the previous key it is BROKEN.
func TestKeyTransition_ForgedByNewKeyHolderBrokenWithPreviousKey(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	parts := strings.Split(f.transitionsValue(), "\x1f")
	require.Len(t, parts, 4)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	forged := bytes.Replace(payload, []byte(`"certified":`), []byte(`"certified":9`), 1)
	require.NotEqual(t, payload, forged)
	macOld := strings.Repeat("ab", 32)
	mac := hmac.New(sha256.New, ktKey2)
	mac.Write([]byte("auditkeytrans-v1\x00new\x00"))
	mac.Write(forged)
	mac.Write([]byte("\x00" + macOld))
	f.setTransitionsValue(strings.Join([]string{"akt-v1", base64.RawURLEncoding.EncodeToString(forged), macOld, hex.EncodeToString(mac.Sum(nil))}, "\x1f"))
	// The in-chain event names the honest record's digest, so the rewrite is
	// already visible without the old key.
	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "does not hold")

	r = f.verifyWith(ktKey2, fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
}

// The new-key holder also rewrites the in-chain event and re-signs every
// checkpoint after it; only the old key still tells.
func TestKeyTransition_OldKeyMACForgedBrokenWithPreviousKey(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	parts := strings.Split(f.transitionsValue(), "\x1f")
	require.Len(t, parts, 4)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	macOld := strings.Repeat("cd", 32)
	mac := hmac.New(sha256.New, ktKey2)
	mac.Write([]byte("auditkeytrans-v1\x00new\x00"))
	mac.Write(payload)
	mac.Write([]byte("\x00" + macOld))
	f.setTransitionsValue(strings.Join([]string{"akt-v1", parts[1], macOld, hex.EncodeToString(mac.Sum(nil))}, "\x1f"))

	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictValid, r.Verdict, "with the new key only this is not detectable: %s", r.Reason)
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "--previous-checkpoint-key-file")
	r = f.verifyWith(ktKey2, fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "old-key signature")
}

// After the recorded v1 -> v2 change, the key changes again to v3 with no
// record (an older binary) and a v3 checkpoint is written: the last record is
// for another epoch.
func TestKeyTransition_RecordForWrongEpochBrokenOffline(t *testing.T) {
	t.Parallel()
	f := rotated(t)
	c3 := core.NewKeyorixCore(f.local)
	c3.SetAuditCheckpointKey(ktKey3, "v3")
	_, _, err := c3.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	r := f.verifyWith(ktKey3)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "another key epoch")
}

// A legacy rotation (no record, no event, by an older binary) keeps today's
// behaviour: VALID under the new key once a fresh checkpoint exists.
func TestKeyTransition_LegacyRotationWithoutRecordUnchanged(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	c2 := core.NewKeyorixCore(f.local)
	c2.SetAuditCheckpointKey(ktKey2, "v2")
	_, _, err = c2.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.False(t, r.KeyTransition.Present)
}
