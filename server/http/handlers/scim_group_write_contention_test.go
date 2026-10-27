package handlers

// #3620 (SCIM-GROUPS-ERR-1): the group handlers answer SQLite write-gate contention
// like the user handlers do (TestSCIM_UserWriteContention_Is503RetryAfter): a SCIM 503
// with Retry-After and the fixed "busy" detail, never a 404/400 the IdP would not
// retry. Contention is raised where the write gate raises it, at the transaction
// start, so nothing was written and a retry is safe: the effect is asserted, not just
// the status.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func TestSCIM_GroupWriteContention_Is503RetryAfter(t *testing.T) {
	contention := fmt.Errorf("begin write transaction (%s): %w", scimInjectedDetail, corestorage.ErrSQLiteWriteContention)

	t.Run("create", func(t *testing.T) {
		h, fs, db := setupSCIMGroupFaultTest(t)
		u1 := provisionUser(t, h, "u1@corp.com")

		fs.Arm(&faultstorage.FaultSpec{Method: "WithTransaction", NthCall: 1, Kind: faultstorage.KindError, Err: contention})
		w := scimGroupDo(h.CreateGroup, http.MethodPost, "", `{"displayName":"Engineers","members":[{"value":"`+u1+`"}]}`)
		require.True(t, fs.Fired())
		fs.Arm(nil)

		assertGroupBusy(t, w)
		var n int64
		require.NoError(t, db.Model(&models.Group{}).Count(&n).Error)
		assert.Zero(t, n, "a contended create must leave no group behind")
	})

	for _, op := range scimGroupOps {
		if !op.mutates {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			h, fs, db := setupSCIMGroupFaultTest(t)
			u1 := provisionUser(t, h, "u1@corp.com")
			u2 := provisionUser(t, h, "u2@corp.com")
			gid := provisionGroup(t, h, "Engineers", u1)

			fs.Arm(&faultstorage.FaultSpec{Method: "WithTransaction", NthCall: 1, Kind: faultstorage.KindError, Err: contention})
			w := op.do(h, gid, u1, u2)
			require.True(t, fs.Fired())
			fs.Arm(nil)

			assertGroupBusy(t, w)
			name, live, members := scimGroupState(t, db, gid)
			assert.Equal(t, "Engineers", name, "a contended write must not rename the group")
			assert.True(t, live, "a contended write must not delete the group")
			assert.EqualValues(t, 1, members, "a contended write must not change the members")
		})
	}
}

// assertGroupBusy pins the 503 contract: SCIM error body with the fixed detail (not the
// injected error text) and the Retry-After the write gate advertises.
func assertGroupBusy(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := assertSCIMErrorBody(t, w, http.StatusServiceUnavailable)
	assert.Equal(t, scimBusyDetail, body["detail"])
	assert.NotContains(t, w.Body.String(), scimInjectedDetail, "the raw error must stay in the server log")
	assert.Equal(t, strconv.Itoa(middleware.WriteContentionRetryAfterSeconds), w.Header().Get("Retry-After"))
}
