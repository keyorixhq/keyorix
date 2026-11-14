// refresh_fault_slot_panic_test.go — the PANIC twin of
// TestRefresh_StorageFaultSlotPolicy (#3968).
//
// A storage panic inside RefreshSession used to unwind to the Recovery 500, so
// the per-IP login-attempt slot RefreshToken reserved was never handed back,
// whatever the call. The rule is the same as for the error kind: a panic before
// the token verdict (GetSessionAny) releases the slot and answers 503; a panic
// after it keeps the slot and answers exactly what the call's error gets (503
// for the owner read, the wrong-token 401 for a write). Driven through the
// production middleware.Recovery, so an unrecovered panic shows up here as the
// 500 a client would get, not as a crashed test.
package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func (e *lockoutOracleEnv) postRefreshRecovered(token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	throughProductionRecovery(e.h.RefreshToken).ServeHTTP(w, r)
	return w
}

// TestRefresh_StoragePanicSlotPolicy drives a panic into every storage call
// refresh makes in each scenario (derived, as in the error-kind table, so a new
// call cannot slip in unclassified) and checks the slot and the answer.
func TestRefresh_StoragePanicSlotPolicy(t *testing.T) {
	ctrlCode, ctrlBody, ctrlSlots := deadTokenControl(t)
	require.Equal(t, http.StatusUnauthorized, ctrlCode)
	require.EqualValues(t, 1, ctrlSlots, "control: a wrong token spends one slot")

	for _, sc := range refreshScenarios {
		probe := newLockoutOracleEnv(t)
		tok := sc.setup(t, probe)
		before := len(probe.fs.Calls())
		probe.postRefreshRecovered(tok)
		seen := map[string]int{}
		type call struct {
			method string
			nth    int
		}
		var calls []call
		for _, c := range probe.fs.Calls()[before:] {
			seen[c.Method]++
			calls = append(calls, call{c.Method, seen[c.Method]})
		}
		require.NotEmpty(t, calls, "%s: refresh made no storage calls?", sc.name)

		for _, c := range calls {
			class, ok := refreshStorageCalls[c.method]
			require.True(t, ok, "%s: refresh now calls storage method %s, which refreshStorageCalls has not classified", sc.name, c.method)
			if class == refreshRateLimit {
				continue
			}
			t.Run(sc.name+"/"+c.method+"#"+string(rune('0'+c.nth)), func(t *testing.T) {
				e := newLockoutOracleEnv(t)
				tok := sc.setup(t, e)
				slotsBefore := e.slots(t)
				e.fs.Arm(&faultstorage.FaultSpec{Method: c.method, NthCall: c.nth, Kind: faultstorage.KindPanic,
					Err: errors.New("injected refresh storage panic")})
				w := e.postRefreshRecovered(tok)
				require.True(t, e.fs.Fired(), "the armed %s#%d panic must have fired", c.method, c.nth)
				e.fs.Arm(nil)
				spent := e.slots(t) - slotsBefore
				require.NotEqual(t, http.StatusInternalServerError, w.Code,
					"a storage panic must take its error twin's path, not the Recovery 500: %s", w.Body.String())

				switch class {
				case refreshPreVerdict:
					assertStorageUnavailable503(t, w)
					assert.Zero(t, spent, "a panic before the token verdict must release the slot, not spend budget")
				case refreshPostVerdictRead:
					assertStorageUnavailable503(t, w)
					assert.EqualValues(t, ctrlSlots, spent, "a panic after the token verdict keeps the slot, like a wrong token")
				case refreshPostVerdict:
					require.Equal(t, ctrlCode, w.Code, w.Body.String())
					assert.Equal(t, ctrlBody, w.Body.String(), "post-verdict panic: same shape as a wrong token")
					assert.EqualValues(t, ctrlSlots, spent, "a panic after the token verdict keeps the slot, like a wrong token")
				}
			})
		}
	}
}
