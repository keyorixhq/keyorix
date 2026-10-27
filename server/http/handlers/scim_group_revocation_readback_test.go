package handlers

// REVIEW-3775 F1: a pure member removal (PATCH remove, or a PUT that only shrinks the
// member set) is a revocation, committed through the owed-audit path (AUDIT-TX-3). The
// response's read-back of the group and its members must not run inside that
// transaction: a failed read there rolled the removal back, and the member kept the
// group's roles. The removal stands whatever the read-back does; PATCH then answers
// 204 No Content (RFC 7644 §3.5.2), PUT answers the SCIM error (a PUT must return the
// resource, §3.5.1, and the IdP's retry is an idempotent no-op).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

var scimRevocationOps = []struct {
	name   string
	status int // the answer when the read-back after the commit fails
	do     func(h *SCIMHandler, gid, u1 string) *httptest.ResponseRecorder
}{
	{"PATCH remove member", http.StatusNoContent, func(h *SCIMHandler, gid, u1 string) *httptest.ResponseRecorder {
		return scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
			`{"Operations":[{"op":"remove","path":"members","value":[{"value":"`+u1+`"}]}]}`)
	}},
	{"PUT empty member set", http.StatusInternalServerError, func(h *SCIMHandler, gid, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.ReplaceGroup, http.MethodPut, gid, `{"displayName":"Engineers","members":[]}`)
	}},
}

// scimReadBackMethods are the two reads of the response's read-back
// (core.readSCIMGroupState): the group row, then its members.
var scimReadBackMethods = []string{"GetGroup", "ListGroupMembers"}

// TestSCIM_GroupRevocationNotRolledBackByReadBack faults the LAST call of each read-back
// method of each pure-removal operation, as an error of every class in scimStorageFaults
// and as a panic, and asserts, on an unfaulted GET, that the member is gone.
func TestSCIM_GroupRevocationNotRolledBackByReadBack(t *testing.T) {
	type fault struct {
		kind faultstorage.FaultKind
		err  error
	}
	faults := map[string]fault{"panic": {faultstorage.KindPanic, fmt.Errorf("storage panic %s", scimInjectedDetail)}}
	for class, ferr := range scimStorageFaults {
		faults[class] = fault{faultstorage.KindError, ferr}
	}
	for _, op := range scimRevocationOps {
		for _, method := range scimReadBackMethods {
			for class, f := range faults {
				t.Run(op.name+"/"+method+"/"+class, func(t *testing.T) {
					// Probe: an unfaulted run, to learn which call of method is the read-back's.
					ph, pfs, _ := setupSCIMGroupFaultTest(t)
					pu1 := provisionUser(t, ph, "u1@corp.com")
					pgid := provisionGroup(t, ph, "Engineers", pu1)
					before := len(pfs.Calls())
					pfs.Arm(nil)
					pw := op.do(ph, pgid, pu1)
					require.Equal(t, http.StatusOK, pw.Code, pw.Body.String())
					assert.Empty(t, groupMemberValues(decodeSCIM(t, pw)))
					nth := 0
					for _, c := range pfs.Calls()[before:] {
						if c.Method == method {
							nth++
						}
					}
					require.Positive(t, nth, "the operation must read the group back")

					h, fs, _ := setupSCIMGroupFaultTest(t)
					u1 := provisionUser(t, h, "u1@corp.com")
					gid := provisionGroup(t, h, "Engineers", u1)
					logBuf := captureLogBuf(t)

					fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: f.kind, Err: f.err})
					w := op.do(h, gid, u1)
					require.True(t, fs.Fired(), "the armed %s fault must have fired", method)
					fs.Arm(nil)

					if op.status == http.StatusNoContent {
						require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
						assert.Empty(t, w.Body.String())
					} else {
						assertSCIMErrorBody(t, w, op.status)
					}
					assert.Contains(t, logBuf.String(), scimInjectedDetail, "the read-back error must be logged for the operator")

					g := scimGroupDo(h.GetGroup, http.MethodGet, gid, "")
					require.Equal(t, http.StatusOK, g.Code, g.Body.String())
					assert.Empty(t, groupMemberValues(decodeSCIM(t, g)), "the removal must stand: a failed read-back must not roll a revocation back")
				})
			}
		}
	}
}
