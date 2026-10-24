// audit_key_transition_prepare_state_test.go — the record prepare writes
// names the state row only when it reads back authentic under the old key in
// the same lock section as the save (AUDIT-ROTATE-TRANSITION-2, review of
// #3648 at 9db14dfe: the save and the record used to be two lock sections).
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The state row is replaced by a forged one (label v1, its pin dropped, junk
// signature) after prepare saved it and before the record names it. The record
// must not name the forged row, so completion does not carry it over and the
// state reads as a discontinuity under the new key.
func TestAuditKeyTransition_StateForgedDuringPrepareNotCarried(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		e.c.auditKeyTransitionHook = func(step string) error {
			if step == aktStepPrepareState {
				fcSetStateValue(t, e.db, aktForgeStateRow(t, fcStateValue(t, e.db)))
			}
			return nil
		}
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		recs, err := parseAuditKeyTransitions(aktTransitionsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		assert.NotEqual(t, auditDigest(fcStateValue(t, e.db)), recs[0].State, "the record names a state row that does not authenticate under the old key")

		c2 := e.restart()
		c2.SetAuditCheckpointKey(aktNewKey, "v2")
		_, _ = c2.CompleteAuditKeyTransition(ctx)
		c2.SeedAuditWatermark(ctx)
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, auditDiscOtherEpoch)
	})
}

// An older state row, authentic under the old key, is put back after prepare
// saved a newer one and before the record names it (a DB writer replaying a
// row from before a recorded failure). Its HMAC is valid, so only the
// generation check stops it: the record must not name it, completion does not
// carry it over, and the state reads as a discontinuity under the new key
// (review of #3648 at 13b481af, L1).
func TestAuditKeyTransition_OlderAuthenticStateDuringPrepareNotCarried(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		older := fcStateValue(t, e.db)
		fcTick(t, e, e.c)
		require.NotEqual(t, older, fcStateValue(t, e.db), "precondition: a newer state row was saved")
		s, _, _ := e.c.decodeAuditVerifyState(older)
		require.NotNil(t, s, "precondition: the older row authenticates under the old key")
		e.c.auditKeyTransitionHook = func(step string) error {
			if step == aktStepPrepareState {
				fcSetStateValue(t, e.db, older)
			}
			return nil
		}
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		recs, err := parseAuditKeyTransitions(aktTransitionsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		assert.NotEqual(t, auditDigest(older), recs[0].State, "the record names an older (replayed) authentic state row")

		c2 := e.restart()
		c2.SetAuditCheckpointKey(aktNewKey, "v2")
		_, _ = c2.CompleteAuditKeyTransition(ctx)
		c2.SeedAuditWatermark(ctx)
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, auditDiscOtherEpoch)
	})
}

// aktForgeStateRow rewrites a state row's payload without the key: the pin is
// dropped and the signature is junk; the key version label stays v1.
func aktForgeStateRow(t *testing.T, val string) string {
	t.Helper()
	parts := strings.Split(val, auditVerifyStateSep)
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(payload, &m))
	delete(m, "pin")
	payload, err = json.Marshal(m)
	require.NoError(t, err)
	return strings.Join([]string{parts[0], base64.RawURLEncoding.EncodeToString(payload), aktForgedSig}, auditVerifyStateSep)
}
