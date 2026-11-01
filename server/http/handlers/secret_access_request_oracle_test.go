package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUTHZ-ORACLE-1 item 2 over REST: PUT /secret-access-requests/{requestId} has no
// route permission gate, so a signed-in caller without admin authority at the
// request's project must get the same status and body for a missing ID, a pending
// secret request, a project/role request and an already-resolved one. Before the
// fix they answered 404, 403, 400 and 409.
func TestResolveSecretAccessRequest_NonAdminIdenticalAnswer(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	ctx := context.Background()

	pending, err := f.core.RequestSecretAccess(ctx, f.secretID, f.requesterID, "need it")
	require.NoError(t, err)
	roleReq, err := f.core.RequestProjectAccess(ctx, f.projectID, f.requesterID, "viewer", "")
	require.NoError(t, err)
	resolved, err := f.core.RequestSecretAccess(ctx, f.secretID, f.approverID, "self")
	require.NoError(t, err)
	_, err = f.core.RejectSecretAccessRequest(ctx, resolved.ID, f.approverID, 0, "no")
	require.NoError(t, err)

	nonAdmin, err := f.st.CreateUser(ctx, &models.User{Username: "sar-oracle-nonadmin", Email: "sar-oracle-nonadmin@example.com", IsActive: true})
	require.NoError(t, err)

	ids := map[string]uint{"missing": 999999, "pending": pending.ID, "project/role": roleReq.ID, "resolved": resolved.ID}
	for _, body := range []string{`{"action":"approve"}`, `{"action":"reject","reason":"no"}`} {
		type answer struct {
			code int
			body string
		}
		got := map[string]answer{}
		for label, id := range ids {
			req := withChiParam(withUserCtxSAR(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(body)), nonAdmin.ID), "requestId", fmt.Sprint(id))
			w := httptest.NewRecorder()
			f.handler.ResolveSecretAccessRequest(w, req)
			got[label] = answer{w.Code, w.Body.String()}
		}
		want := got["missing"]
		assert.Equal(t, http.StatusNotFound, want.code, want.body)
		for label, a := range got {
			assert.Equal(t, want, a, "%s: %s answers differently from a missing ID", body, label)
		}
	}
}
