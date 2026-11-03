// audit_verify_state_rolling_upgrade_marker_test.go — the in-chain marker names
// the state generation that placed the state (#3708). An older replica's
// re-sign is recognised only above that generation; every other unplaced row
// still latches (audit_verify_state_rolling_upgrade_test.go has the re-sign
// itself).
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The text a server from before #3708 gave the marker.
const unnamedMarkerText = "audit verification state in use: a missing verification state row is reported as a discontinuity from now on"

func newestMarker(t *testing.T, db *gorm.DB) models.AuditEvent {
	t.Helper()
	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", auditVerifyStateMarkerEvent).Order("id DESC").First(&ev).Error)
	return ev
}

func TestAuditVerifyMarkerGen(t *testing.T) {
	for in, want := range map[string]uint64{
		auditVerifyMarkerText(7):                                   7,
		auditVerifyMarkerText(18446744073709):                      18446744073709,
		unnamedMarkerText:                                          0,
		"audit verification state in use (state generation 0): x":  0,
		"x audit verification state in use (state generation 3): ": 0,
	} {
		assert.Equal(t, want, auditVerifyMarkerGen(in), in)
	}
}

// The reason this binary restarts a re-sign with is the one rejection an
// unplaced row may carry above the marker; any other text latches.
func TestAuditVerifyResavedRE(t *testing.T) {
	require.Regexp(t, auditVerifyResavedRE, fmt.Sprintf(auditVerifyResavedText, uint64(18446744073709551615), 1))
	for _, r := range []string{
		"the persisted verification state is missing although this server already read generation 3 (deleted or rolled back) and was ignored",
		"the persisted verification state is malformed and was ignored",
		"x " + fmt.Sprintf(auditVerifyResavedText, 4, 3),
		fmt.Sprintf(auditVerifyResavedText, 0, 3),
	} {
		require.NotRegexp(t, auditVerifyResavedRE, r)
	}
}

// A row signed before this binary placed the state (generation not above the
// marker's) latches even when it binds the current trail.
func TestAuditVerifyStateRollingUpgrade_PreUpgradeRowLatches(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		gen := auditVerifyMarkerGen(newestMarker(t, e.db).Description)
		require.Positive(t, gen, "the marker names the generation that placed the state")
		fcSetStateValue(t, e.db, olderReplicaStateValue(t, e.c, fcStateValue(t, e.db), gen))
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
		assertDiscontinuitySticky(t, e, c, "before a recorded break")
	})
}

// While the newest marker names no generation (appended by a server from before
// #3708), nothing places an unplaced row: it latches, as before.
func TestAuditVerifyStateRollingUpgrade_UnnamedMarkerLatches(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		e.c.writeAuditEventFull(context.Background(), auditVerifyStateMarkerEvent, nil, nil, nil, "", unnamedMarkerText)
		olderReplicaResave(t, e, e.c)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
	})
}

// A deployment whose newest marker names no generation gets a named one with
// its next save, so an older replica's re-sign after it (a later rollback and
// re-upgrade) heals too.
func TestAuditVerifyStateRollingUpgrade_UnnamedMarkerIsRenamed(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		e.c.writeAuditEventFull(context.Background(), auditVerifyStateMarkerEvent, nil, nil, nil, "", unnamedMarkerText)
		require.Zero(t, auditVerifyMarkerGen(newestMarker(t, e.db).Description), "precondition: the newest marker names no generation")
		c := e.restart()
		fcTick(t, e, c)
		require.Positive(t, auditVerifyMarkerGen(newestMarker(t, e.db).Description))
		olderReplicaResave(t, e, c)
		c2 := e.restart()
		assertNotBroken(t, e, c2)
		fcTick(t, e, c2)
		assertNotBroken(t, e, c2)
	})
}

// A failure event naming no generation (an older replica's) above the marker,
// with a re-signed row that carries no failure: the row may predate that break,
// so it latches.
func TestAuditVerifyStateRollingUpgrade_UnnamedFailureAboveMarkerLatches(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		olderReplicaResave(t, e, e.c)
		e.c.writeAuditEventFailedFull(context.Background(), auditChainVerificationFailedEvent, nil, nil, nil, "",
			"audit chain verification failed (rolling): entry_hash mismatch")
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
	})
}
