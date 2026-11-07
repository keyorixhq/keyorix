// share_revoke_admin_test.go — DELETE /shares/{id} is allowed to the secret's owner and to
// an administrator of the secret's scope; PUT /shares/{id} stays owner-only. A project
// member who merely holds secrets.write is refused on both.
//
// Driven through the real router and real sessions (ownedShareFixture): olga owns
// "olga-p" in P and shared it with alice; wendy holds secrets.read + secrets.write at P.
package http

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShareRevoke_AdminOverREST(t *testing.T) {
	f := newOwnedShareFixture(t)
	sharePath := fmt.Sprintf("/api/v1/shares/%d", f.olgaShareP)
	stillThere := func() bool {
		code, out, raw := f.owned(t, f.ownerTok, "")
		require.Equal(t, http.StatusOK, code, raw)
		return slices.Contains(shareIDs(out.Data.Data), f.olgaShareP)
	}
	require.True(t, stillThere())

	// A write-tier project member who is not the owner is refused on update and revoke.
	code, raw := doMachineRequest(t, f.d.srv, f.writerTok, http.MethodPut, sharePath, []byte(`{"permission":"write"}`))
	assert.Equal(t, http.StatusForbidden, code, raw)
	code, raw = doMachineRequest(t, f.d.srv, f.writerTok, http.MethodDelete, sharePath, nil)
	assert.Equal(t, http.StatusForbidden, code, raw)
	require.True(t, stillThere(), "a refused revoke must not remove the share")

	// An administrator may not change the share: update stays owner-only.
	code, raw = doMachineRequest(t, f.d.srv, f.d.adminTok, http.MethodPut, sharePath, []byte(`{"permission":"write"}`))
	assert.Equal(t, http.StatusForbidden, code, raw)
	require.True(t, stillThere())

	// An administrator may revoke it.
	code, raw = doMachineRequest(t, f.d.srv, f.d.adminTok, http.MethodDelete, sharePath, nil)
	require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, code, raw)
	assert.False(t, stillThere(), "the owner no longer lists the revoked share")
}

func TestShareRevoke_OwnerOverREST(t *testing.T) {
	f := newOwnedShareFixture(t)
	code, raw := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", f.olgaShareP), nil)
	require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, code, raw)
}
