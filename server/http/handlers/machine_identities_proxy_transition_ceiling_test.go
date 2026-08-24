// machine_identities_proxy_transition_ceiling_test.go — G80 overnight campaign,
// Tier 1 Group A fix #1. TransitionMachineIdentityStateProxy's raw conditional
// write (WHERE id=? AND state=fromState) had no legality check of its own: a
// caller could resurrect a revoked machine identity (revoked is supposed to be
// terminal) or jump straight from pending to suspended, skipping every rule
// core.TransitionMachineIdentity's transaction body (transitionMachineInTx)
// enforces. Fixed by calling core.IsValidMachineTransition(fromState, toState)
// before the storage write — that check needs only the (from, to) pair, both
// already on the wire, so no RemoteStorage wire-protocol change was needed (see
// docs/g80-raw-storage-bypass-triage.md and the RemoteStorage impact check in
// this campaign's overnight session for why this one was safe to fix without
// coordinating a client-side change).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransitionMachineIdentityStateProxy_RejectsIllegalTransition_RealServer
// creates a real machine identity, legitimately revokes it via the proxy (the
// same code path a downstream RemoteStorage node's core.TransitionMachineIdentity
// call would relay), then attempts to un-revoke it via the SAME proxy — an
// illegal transition (revoked is terminal) that a raw, unguarded conditional
// write cannot distinguish from a legal one, since the persisted state genuinely
// does match the caller-supplied from_state.
func TestTransitionMachineIdentityStateProxy_RejectsIllegalTransition_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	ctx := t.Context()

	proj, err := cs.CreateProject(ctx, "g80-transition-ceiling-proj", "")
	require.NoError(t, err)
	m, err := cs.CreateMachineIdentity(ctx, proj.ID, "g80-transition-ceiling-machine", core.MachineTypeOther, "", "", 0)
	require.NoError(t, err)
	require.Equal(t, core.MachineActive, m.State)

	// Legal: active -> revoked. Must still succeed after the fix.
	revokeBody, err := json.Marshal(map[string]interface{}{
		"machine_identity": map[string]interface{}{
			"project_id":    proj.ID,
			"name":          m.Name,
			"identity_type": m.IdentityType,
			"state":         core.MachineRevoked,
		},
		"from_state": core.MachineActive,
	})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(revokeBody)), map[string]string{"id": machineUintToStr(m.ID)})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	require.Equal(t, 200, w.Code, "legal active->revoked transition must still succeed: %s", w.Body.String())

	// Illegal: revoked -> active (un-revoke). Must be rejected.
	unrevokeBody, err := json.Marshal(map[string]interface{}{
		"machine_identity": map[string]interface{}{
			"project_id":    proj.ID,
			"name":          m.Name,
			"identity_type": m.IdentityType,
			"state":         core.MachineActive,
		},
		"from_state": core.MachineRevoked,
	})
	require.NoError(t, err)
	req2 := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(unrevokeBody)), map[string]string{"id": machineUintToStr(m.ID)})
	w2 := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w2, req2)
	assert.Equal(t, 400, w2.Code, "revoked->active is illegal (revoked is terminal) and must be rejected, not silently applied")

	reloaded, err := cs.Storage().GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MachineRevoked, reloaded.State, "the illegal transition must not have persisted")
}
