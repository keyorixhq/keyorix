package handlers

// SCIM-TAILS-1 item 1: renderGroup (GET one, POST, PUT, PATCH) and ListGroups read the
// member list with GetGroupMembers and used to discard its error (`members, _ :=`). A
// storage fault there rendered the group with an EMPTY members array at 200/201, which
// an IdP reads as "this group has no members" and answers by removing them all. The
// failure must be a 500 with the SCIM error body and no group resource.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// scimMemberReadOp is one handler call that ends in a member-list read.
type scimMemberReadOp struct {
	name string
	// do runs the call against group gid (members: u1), u2 is a SCIM-managed non-member.
	do func(h *SCIMHandler, gid, u1, u2 string) *httptest.ResponseRecorder
}

var scimMemberReadOps = []scimMemberReadOp{
	{"GET one group", func(h *SCIMHandler, gid, _, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.GetGroup, http.MethodGet, gid, "")
	}},
	{"GET list", func(h *SCIMHandler, _, _, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.ListGroups, http.MethodGet, "", "")
	}},
	{"POST create", func(h *SCIMHandler, _, u1, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.CreateGroup, http.MethodPost, "", `{"displayName":"Created","members":[{"value":"`+u1+`"}]}`)
	}},
	{"PUT replace", func(h *SCIMHandler, gid, u1, u2 string) *httptest.ResponseRecorder {
		return scimGroupDo(h.ReplaceGroup, http.MethodPut, gid,
			`{"displayName":"Engineers","members":[{"value":"`+u1+`"},{"value":"`+u2+`"}]}`)
	}},
	{"PATCH add member", func(h *SCIMHandler, gid, _, u2 string) *httptest.ResponseRecorder {
		return scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
			`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+u2+`"}]}]}`)
	}},
}

// TestSCIM_GroupMemberReadError_Is500 faults the LAST ListGroupMembers call of each
// operation (the render's read; PUT also reads the members earlier, in core) and asserts
// a 500 SCIM error with no group resource, for every class in scimStorageFaults.
func TestSCIM_GroupMemberReadError_Is500(t *testing.T) {
	for _, op := range scimMemberReadOps {
		for kind, ferr := range scimStorageFaults {
			t.Run(op.name+"/"+kind, func(t *testing.T) {
				// Probe: an unfaulted run, to learn which ListGroupMembers call is the render's.
				ph, pfs, _ := setupSCIMGroupFaultTest(t)
				pu1 := provisionUser(t, ph, "u1@corp.com")
				pu2 := provisionUser(t, ph, "u2@corp.com")
				pgid := provisionGroup(t, ph, "Engineers", pu1)
				before := len(pfs.Calls())
				pfs.Arm(nil)
				require.Less(t, op.do(ph, pgid, pu1, pu2).Code, 300)
				nth := 0
				for _, c := range pfs.Calls()[before:] {
					if c.Method == "ListGroupMembers" {
						nth++
					}
				}
				require.Positive(t, nth, "the operation must read the group's members")

				h, fs, _ := setupSCIMGroupFaultTest(t)
				u1 := provisionUser(t, h, "u1@corp.com")
				u2 := provisionUser(t, h, "u2@corp.com")
				gid := provisionGroup(t, h, "Engineers", u1)
				logBuf := captureLogBuf(t)

				fs.Arm(&faultstorage.FaultSpec{Method: "ListGroupMembers", NthCall: nth, Kind: faultstorage.KindError, Err: ferr})
				w := op.do(h, gid, u1, u2)
				require.True(t, fs.Fired(), "the armed ListGroupMembers fault must have fired")
				fs.Arm(nil)

				body := assertSCIMErrorBody(t, w, http.StatusInternalServerError)
				assert.Equal(t, clientSafe(ferr), body["detail"])
				assert.NotContains(t, body, "members", "a failed member read must not render a group")
				assert.NotContains(t, body, "Resources", "a failed member read must not render a list")
				assert.Contains(t, logBuf.String(), scimInjectedDetail, "the real error must be logged for the operator")
			})
		}
	}
}
