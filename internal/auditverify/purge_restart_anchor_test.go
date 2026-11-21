package auditverify_test

// #4351: a sanctioned retention purge that empties the table (case 1), or that
// removes the row the latest checkpoint certified as head (case 2), verifies
// VALID online and offline alike; every way of passing an unsanctioned removal
// off as such a purge still reads BROKEN on both. Fixtures are written through
// the real core/store path (differential_test.go), on a fake clock.

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const retentionAnchorMetaKey = "audit_retention_anchor"

// clockFixture is a diffFixture whose core runs on a settable fake clock that
// starts long before the real wall clock (system events such as the purge's own
// row are stamped with the real clock, so no purge here ever removes them).
type clockFixture struct {
	*diffFixture
	now time.Time
}

func newClockFixture(t *testing.T) *clockFixture {
	t.Helper()
	f := &clockFixture{diffFixture: newDiffFixture(t), now: time.Date(2020, 1, 1, 10, 0, 0, 0, time.UTC)}
	f.core.SetClockForTesting(func() time.Time { return f.now })
	return f
}

func (f *clockFixture) appendAt(n int) {
	f.t.Helper()
	tr := true
	for range n {
		f.nextID++
		require.NoError(f.t, f.local.LogAuditEvent(f.ctx, &models.AuditEvent{
			EventType: "secret.read", Description: "event", Success: &tr, EventTime: f.now, ActorType: "user",
		}))
	}
}

func (f *clockFixture) checkpoint(want int64) {
	f.t.Helper()
	cp, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(f.t, err)
	require.NotNil(f.t, cp)
	require.Equal(f.t, want, cp.ChainedEvents)
}

func (f *clockFixture) purge(days int, wantDeleted int64) {
	f.t.Helper()
	res, err := f.core.PurgeAuditLogs(f.ctx, core.AuditLogRetentionConfig{RetentionDays: days})
	require.NoError(f.t, err)
	require.Equal(f.t, wantDeleted, res.DeletedCount)
}

// verdicts runs the online and the offline (checkpoint key) verifier.
func (f *clockFixture) verdicts() (online bool, onlineReason string, offline *auditverify.Result) {
	f.t.Helper()
	v := f.oracle()
	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(f.t, err)
	return v.Valid, v.Reason, got
}

func (f *clockFixture) requireValid(chained, purged int64) {
	f.t.Helper()
	online, reason, got := f.verdicts()
	require.True(f.t, online, "online: %s", reason)
	require.Equal(f.t, auditverify.VerdictValid, got.Verdict, "offline: %s", got.Reason)
	require.Equal(f.t, chained, got.ChainedEvents)
	require.Equal(f.t, purged, got.PurgedEvents)
}

func (f *clockFixture) requireBroken(why string) (onlineReason, offlineReason string) {
	f.t.Helper()
	online, reason, got := f.verdicts()
	require.False(f.t, online, "%s: online verifier accepted it", why)
	require.Equal(f.t, auditverify.VerdictBroken, got.Verdict, "%s: offline said %s (%s); online said %q", why, got.Verdict, got.Reason, reason)
	return reason, got.Reason
}

// requireBelowRestartAnchor: only the restart anchor's RowID binding catches
// these (every count and head check passes), on both verifiers.
func (f *clockFixture) requireBelowRestartAnchor(why string) {
	f.t.Helper()
	on, off := f.requireBroken(why)
	require.Contains(f.t, on, "the first id the signed retention anchor says survived")
	require.Contains(f.t, off, "the first id the signed retention anchor says survived")
}

// case1: 3 events, a checkpoint certifying them, then a purge that removes
// all 3 (the table is empty until the purge's own row is appended).
func case1(t *testing.T) *clockFixture {
	t.Helper()
	f := newClockFixture(t)
	f.appendAt(3)
	f.checkpoint(3)
	f.now = f.now.AddDate(0, 0, 10)
	f.purge(7, 3)
	return f
}

// case2 is the reproduction from #4351: one event, two checkpoints, a purge
// that removes nothing, then one that removes event #1, the head the latest
// checkpoint certified; the first purge's row survives.
func case2(t *testing.T) *clockFixture {
	t.Helper()
	f := newClockFixture(t)
	f.appendAt(1)
	f.checkpoint(1)
	f.checkpoint(1)
	f.now = f.now.AddDate(0, 0, 15)
	f.purge(15, 0)
	f.now = f.now.AddDate(0, 0, 10).Add(time.Hour)
	f.purge(25, 1)
	return f
}

func TestPurge4351_EmptyingPurgeVerifies(t *testing.T) {
	t.Parallel()
	f := case1(t)
	f.requireValid(1, 3) // the purge's own row, plus 3 signed as purged
	// No key: the chain restarted at genesis, so nothing is unauthenticated.
	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, got.Reason)
	require.Zero(t, got.PurgedEvents, "never credited without the key")
	// A new checkpoint certifies chained + purged, and still verifies.
	f.checkpoint(4)
	f.requireValid(1, 3)
}

func TestPurge4351_PurgeOfCertifiedHeadVerifies(t *testing.T) {
	t.Parallel()
	f := case2(t)
	f.requireValid(2, 1) // both purge rows survive; event #1 signed as purged
	f.checkpoint(3)
	f.requireValid(2, 1)
}

// Rows removed with no anchor at all: the delete is unsanctioned.
func TestPurge4351_Negative_NoAnchor(t *testing.T) {
	t.Parallel()
	for name, build := range map[string]func(*testing.T) *clockFixture{"case 1": case1, "case 2": case2} {
		t.Run(name, func(t *testing.T) {
			f := build(t)
			f.exec("DELETE FROM system_metadata WHERE key = ?", retentionAnchorMetaKey)
			f.requireBroken("purge anchor deleted")
		})
	}
	t.Run("raw delete of every row", func(t *testing.T) {
		f := newClockFixture(t)
		f.appendAt(3)
		f.checkpoint(3)
		f.exec("DELETE FROM audit_events")
		f.requireBroken("every row deleted outside a purge")
	})
	t.Run("raw delete of the certified head", func(t *testing.T) {
		f := newClockFixture(t)
		f.appendAt(1)
		f.checkpoint(1)
		f.appendAt(2)
		f.exec("DELETE FROM audit_events WHERE id = 1")
		f.requireBroken("certified head deleted outside a purge")
	})
}

// An anchor whose signed count was raised (or lowered) no longer
// authenticates, so nothing is credited.
func TestPurge4351_Negative_WrongCount(t *testing.T) {
	t.Parallel()
	for name, build := range map[string]func(*testing.T) *clockFixture{"case 1": case1, "case 2": case2} {
		for _, delta := range []int{-1, +1, +100} {
			t.Run(fmt.Sprintf("%s %+d", name, delta), func(t *testing.T) {
				f := build(t)
				parts := strings.Split(anchorValue(t, f.diffFixture), "\x1f")
				require.Len(t, parts, 7)
				n, err := strconv.Atoi(parts[4])
				require.NoError(t, err)
				parts[4] = strconv.Itoa(n + delta)
				require.NoError(t, f.local.SetSystemMetadata(f.ctx, retentionAnchorMetaKey, strings.Join(parts, "\x1f")))
				f.requireBroken("anchor count changed")
			})
		}
	}
}

// An anchor that belongs to another chain: signed under another deployment's
// key, or signed under this key but for another chain's rows.
func TestPurge4351_Negative_AnchorFromAnotherChain(t *testing.T) {
	t.Parallel()
	t.Run("other key", func(t *testing.T) {
		other := newClockFixture(t)
		other.core.SetAuditCheckpointKey(bytes.Repeat([]byte{0x9}, 32), "v1")
		other.appendAt(3)
		other.now = other.now.AddDate(0, 0, 10)
		other.purge(7, 3)

		f := newClockFixture(t)
		f.appendAt(3)
		f.checkpoint(3)
		f.exec("DELETE FROM audit_events")
		require.NoError(t, f.local.SetSystemMetadata(f.ctx, retentionAnchorMetaKey, anchorValue(t, other.diffFixture)))
		f.requireBroken("restart anchor signed under another key")
	})
	t.Run("same key, restart anchor over rows it says were purged", func(t *testing.T) {
		other := case1(t) // restart anchor at RowID 4, 3 purged

		f := newClockFixture(t)
		f.appendAt(5)
		f.checkpoint(5)
		require.NoError(t, f.local.SetSystemMetadata(f.ctx, retentionAnchorMetaKey, anchorValue(t, other.diffFixture)))
		f.requireBelowRestartAnchor("another chain's restart anchor")
	})
	t.Run("same key, re-anchor naming another chain's row", func(t *testing.T) {
		other := case2(t) // re-anchor at the first purge's row

		f := newClockFixture(t)
		f.appendAt(1)
		f.checkpoint(1)
		f.appendAt(1)
		f.exec("DELETE FROM audit_events WHERE id = 1")
		require.NoError(t, f.local.SetSystemMetadata(f.ctx, retentionAnchorMetaKey, anchorValue(t, other.diffFixture)))
		f.requireBroken("another chain's re-anchor")
	})
}

// A restart anchor binds every surviving row to an id at or above its RowID:
// a row put back below it is not part of the restarted chain.
func TestPurge4351_Negative_RowBelowRestartAnchor(t *testing.T) {
	t.Parallel()
	f := case1(t)
	// The purge's own row (the restarted chain's genesis row), put back as #2.
	f.exec("CREATE TEMP TABLE moved AS SELECT * FROM audit_events ORDER BY id LIMIT 1")
	f.exec("UPDATE moved SET id = 2")
	f.exec("DELETE FROM audit_events")
	f.exec("INSERT INTO audit_events SELECT * FROM moved")
	f.requireBelowRestartAnchor("row below the restart anchor")
}
