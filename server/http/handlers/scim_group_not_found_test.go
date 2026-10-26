package handlers

// #3620: a 404 on the SCIM Group endpoints is reserved for "positively absent". The
// storage layer says so with corestorage.ErrGroupNotFound; everything else is a 5xx
// (scim_group_storage_error_status_test.go).

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestSCIM_GroupNotFound_Is404(t *testing.T) {
	for _, op := range scimGroupOps {
		t.Run(op.name+"/no such id", func(t *testing.T) {
			h, _, _ := setupSCIMGroupFaultTest(t)
			u1 := provisionUser(t, h, "u1@corp.com")
			u2 := provisionUser(t, h, "u2@corp.com")
			body := assertSCIMErrorBody(t, op.do(h, "999999", u1, u2), http.StatusNotFound)
			assert.Nil(t, body["scimType"])
		})
		t.Run(op.name+"/gone between the read and the write", func(t *testing.T) {
			h, fs, _ := setupSCIMGroupFaultTest(t)
			u1 := provisionUser(t, h, "u1@corp.com")
			u2 := provisionUser(t, h, "u2@corp.com")
			gid := provisionGroup(t, h, "Engineers", u1)
			fs.Arm(&faultstorage.FaultSpec{Method: "GetGroup", NthCall: 1, Kind: faultstorage.KindError,
				Err: fmt.Errorf("group not found: %w", corestorage.ErrGroupNotFound)})
			w := op.do(h, gid, u1, u2)
			require.True(t, fs.Fired())
			fs.Arm(nil)
			assertSCIMErrorBody(t, w, http.StatusNotFound)
		})
	}
}
