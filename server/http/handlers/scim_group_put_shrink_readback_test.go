package handlers

// GRPC-OUTAGE-TAILS-1 item 4 (#3773): a PUT that shrinks a group to a NON-empty member
// set commits the removal; if the read-back for the response then fails, the PUT still
// answers 200 with the group as the write left it (the member that was kept, not the
// one that was removed, not an empty list that would make the IdP drop everyone), and
// the membership is what the response says.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestSCIM_ReplaceGroupShrink_ReadBackFaultStill200WithKeptMembers(t *testing.T) {
	put := func(h *SCIMHandler, gid, keep string) *httptest.ResponseRecorder {
		return scimGroupDo(h.ReplaceGroup, http.MethodPut, gid, `{"displayName":"Engineers","members":[{"value":"`+keep+`"}]}`)
	}

	// Probe an unfaulted run for the call number of the read-back's ListGroupMembers.
	ph, pfs, _ := setupSCIMGroupFaultTest(t)
	pu1, pu2 := provisionUser(t, ph, "u1@corp.com"), provisionUser(t, ph, "u2@corp.com")
	pgid := provisionGroup(t, ph, "Engineers", pu1, pu2)
	before := len(pfs.Calls())
	pw := put(ph, pgid, pu2)
	require.Equal(t, http.StatusOK, pw.Code, pw.Body.String())
	nth := 0
	for _, c := range pfs.Calls()[before:] {
		if c.Method == "ListGroupMembers" {
			nth++
		}
	}
	require.Positive(t, nth)

	h, fs, _ := setupSCIMGroupFaultTest(t)
	u1, u2 := provisionUser(t, h, "u1@corp.com"), provisionUser(t, h, "u2@corp.com")
	gid := provisionGroup(t, h, "Engineers", u1, u2)
	fs.Arm(&faultstorage.FaultSpec{Method: "ListGroupMembers", NthCall: nth, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
	w := put(h, gid, u2)
	require.True(t, fs.Fired(), "the read-back fault must have fired")
	fs.Arm(nil)

	require.Equal(t, http.StatusOK, w.Code, "a committed change is not a failure: %s", w.Body.String())
	body := decodeSCIM(t, w)
	assert.Equal(t, gid, body["id"])
	assert.Equal(t, "Engineers", body["displayName"])
	assert.Equal(t, []string{u2}, groupMemberValues(body), "the response names the member the PUT kept")

	// Effect: the stored membership is exactly what the 200 said.
	g := scimGroupDo(h.GetGroup, http.MethodGet, gid, "")
	require.Equal(t, http.StatusOK, g.Code, g.Body.String())
	assert.Equal(t, []string{u2}, groupMemberValues(decodeSCIM(t, g)))
}
