// transfer_ownership_oracle_test.go — OWNERSHIP-ORACLE-1 over REST: a caller who
// passes the route gate (scoped secrets.write) but may not transfer the secret gets
// the same status and body for every new_owner_id: an existing user, a missing one,
// and the current owner. Before the fix the last two answered 404 "new owner N not
// found" and 400 "already owned", so the refusal said which IDs are users and who
// owns the secret.
//
// No gRPC RPC reaches core.TransferSecretOwnership (the share service has none), so
// REST is the only transport to pin.
package http

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransferOwnership_UnauthorizedActorIdenticalRefusalOverREST(t *testing.T) {
	f := newOwnedShareFixture(t)
	secretID := mustShareSecretID(t, f, f.olgaShareP) // owned by olga, in P
	path := fmt.Sprintf("/api/v1/secrets/%d/transfer-ownership", secretID)

	// wendy holds secrets.write at P (passes the route gate) but is not the owner.
	targets := map[string]uint{
		"existing user": f.d.aliceID,
		"missing user":  999999,
		"current owner": f.ownerID,
	}
	type answer struct {
		code int
		body string
	}
	got := map[string]answer{}
	for label, newOwner := range targets {
		code, raw := doMachineRequest(t, f.d.srv, f.writerTok, http.MethodPost, path,
			[]byte(fmt.Sprintf(`{"new_owner_id":%d}`, newOwner)))
		require.Equal(t, http.StatusForbidden, code, "%s: %s", label, raw)
		got[label] = answer{code, raw}
	}
	want := got["existing user"]
	for label, a := range got {
		assert.Equal(t, want, a, "%s answers differently from an existing user", label)
	}

	// The owner still gets the specific answers.
	code, raw := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodPost, path, []byte(`{"new_owner_id":999999}`))
	assert.Equal(t, http.StatusNotFound, code, raw)
	code, raw = doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodPost, path,
		[]byte(fmt.Sprintf(`{"new_owner_id":%d}`, f.ownerID)))
	assert.Equal(t, http.StatusBadRequest, code, raw)
}
