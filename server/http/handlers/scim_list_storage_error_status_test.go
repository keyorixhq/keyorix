package handlers

// SCIM-JIT-TAILS-1 (#3494 follow-up): the list endpoints are the last SCIM handlers
// without a storage-fault table. An IdP reconciles with GET /Users and GET /Groups
// (paged and `userName eq` / `displayName eq` filtered), so a storage failure there
// must be a 500 with the generic detail, never a 404 or an empty 200 that reads as
// "the directory is empty", and never the driver text. The not-found sentinel on
// the filtered user lookup is the one benign case: no match is a 200 with no
// resources, not a 404.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

type scimListOp struct {
	name   string
	method string // storage call the fault is armed on
	do     func(h *SCIMHandler) *httptest.ResponseRecorder
}

func scimListDo(h http.HandlerFunc, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

var scimListOps = []scimListOp{
	{"users paged", "ListUsers", func(h *SCIMHandler) *httptest.ResponseRecorder {
		return scimListDo(h.ListUsers, "/scim/v2/Users")
	}},
	{"users filtered", "GetUserByEmail", func(h *SCIMHandler) *httptest.ResponseRecorder {
		return scimListDo(h.ListUsers, `/scim/v2/Users?filter=userName%20eq%20%22u%40corp.com%22`)
	}},
	{"groups paged", "ListGroupsPage", func(h *SCIMHandler) *httptest.ResponseRecorder {
		return scimListDo(h.ListGroups, "/scim/v2/Groups")
	}},
	{"groups filtered", "ListGroups", func(h *SCIMHandler) *httptest.ResponseRecorder {
		return scimListDo(h.ListGroups, `/scim/v2/Groups?filter=displayName%20eq%20%22Eng%22`)
	}},
	{"groups paged, member read", "ListGroupMembers", func(h *SCIMHandler) *httptest.ResponseRecorder {
		return scimListDo(h.ListGroups, "/scim/v2/Groups")
	}},
}

// TestSCIM_ListStorageError_Is500NotNotFound: every storage error class on every list
// endpoint answers a 500 SCIM error body with the generic detail and nothing else.
func TestSCIM_ListStorageError_Is500NotNotFound(t *testing.T) {
	for _, op := range scimListOps {
		for kind, ferr := range scimStorageFaults {
			t.Run(op.name+"/"+kind, func(t *testing.T) {
				h, fs, _ := setupSCIMFaultTest(t)
				u := provisionUser(t, h, "u@corp.com")
				provisionGroup(t, h, "Eng", u)
				logBuf := captureLogBuf(t)

				fs.Arm(&faultstorage.FaultSpec{Method: op.method, NthCall: 1, Kind: faultstorage.KindError, Err: ferr})
				w := op.do(h)
				require.True(t, fs.Fired(), "the armed %s fault must have fired", op.method)
				fs.Arm(nil)

				body := assertSCIMErrorBody(t, w, http.StatusInternalServerError)
				assert.Equal(t, clientSafe(ferr), body["detail"])
				assert.Contains(t, logBuf.String(), scimInjectedDetail, "the real error must be logged for the operator")
			})
		}
	}
}

// TestSCIM_ListFilteredUser_NotFoundSentinelIsEmpty200: an absent user is the empty
// list RFC 7644 specifies for a filter with no match, not a 404.
func TestSCIM_ListFilteredUser_NotFoundSentinelIsEmpty200(t *testing.T) {
	h, fs, _ := setupSCIMFaultTest(t)
	fs.Arm(&faultstorage.FaultSpec{Method: "GetUserByEmail", NthCall: 1, Kind: faultstorage.KindError,
		Err: fmt.Errorf("user not found: %w", corestorage.ErrUserNotFound)})
	w := scimListDo(h.ListUsers, `/scim/v2/Users?filter=userName%20eq%20%22nobody%40corp.com%22`)
	require.True(t, fs.Fired())
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.EqualValues(t, 0, decodeSCIM(t, w)["totalResults"])
}
