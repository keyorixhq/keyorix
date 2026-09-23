// bulk_remote_test.go — proves bulk-approve, bulk-reject, and
// rejection-templates delete are dual-mode like every other request
// subcommand (runReview, runTmplList, runTmplAdd all check
// common.NewRemoteClient() first): with a remote server configured, these
// three must hit the server's REST routes instead of falling through to the
// embedded core.
package request

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBulkServer records which of the three routes under test were hit and
// returns a well-formed success envelope for each.
type fakeBulkServer struct {
	approveHit bool
	rejectHit  bool
	deleteHit  bool
}

func newFakeBulkServer(t *testing.T, rec *fakeBulkServer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/access-requests/bulk-approve", func(w http.ResponseWriter, r *http.Request) {
		rec.approveHit = true
		_, _ = w.Write([]byte(`{"data":{"result":{"approved":[1,2],"failed":[]}}}`))
	})
	mux.HandleFunc("/api/v1/access-requests/bulk-reject", func(w http.ResponseWriter, r *http.Request) {
		rec.rejectHit = true
		_, _ = w.Write([]byte(`{"data":{"result":{"rejected":[1,2],"failed":[]}}}`))
	})
	mux.HandleFunc("/api/v1/rejection-reason-templates/7", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		rec.deleteHit = true
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pointAtFakeServer configures the CLI's remote resolver at srv via env vars,
// the same mechanism every other dual-mode request command relies on
// (common.NewRemoteClient() reads KEYORIX_SERVER/KEYORIX_TOKEN).
func pointAtFakeServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
}

// TestRunBulkApprove_UsesRemoteClientWhenConfigured is the red/green case for
// GAP-F-BULK: with a remote server configured, bulk-approve must go through
// POST /api/v1/access-requests/bulk-approve instead of silently falling
// through to the embedded core (which, in a fresh temp dir with no seeded
// admin, would error on --by resolution without ever touching the server).
func TestRunBulkApprove_UsesRemoteClientWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	rec := &fakeBulkServer{}
	pointAtFakeServer(t, newFakeBulkServer(t, rec))

	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs, bulkApproveBy = origIDs, origBy }()
	bulkApproveIDs = "1,2"
	bulkApproveBy = "admin@example.com"

	err := runBulkApprove(nil, nil)
	require.NoError(t, err)
	assert.True(t, rec.approveHit, "expected POST /api/v1/access-requests/bulk-approve to be called")
}

// TestRunBulkReject_UsesRemoteClientWhenConfigured mirrors the approve case
// for POST /api/v1/access-requests/bulk-reject.
func TestRunBulkReject_UsesRemoteClientWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	rec := &fakeBulkServer{}
	pointAtFakeServer(t, newFakeBulkServer(t, rec))

	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() { bulkRejectIDs, bulkRejectBy, bulkRejectReason = origIDs, origBy, origReason }()
	bulkRejectIDs = "1,2"
	bulkRejectBy = "admin@example.com"
	bulkRejectReason = "no longer needed"

	err := runBulkReject(nil, nil)
	require.NoError(t, err)
	assert.True(t, rec.rejectHit, "expected POST /api/v1/access-requests/bulk-reject to be called")
}

// TestRunTmplDelete_UsesRemoteClientWhenConfigured mirrors runTmplList's and
// runTmplAdd's existing remote checks for DELETE
// /api/v1/rejection-reason-templates/{id}.
func TestRunTmplDelete_UsesRemoteClientWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	rec := &fakeBulkServer{}
	pointAtFakeServer(t, newFakeBulkServer(t, rec))

	origBy := tmplDeleteBy
	defer func() { tmplDeleteBy = origBy }()
	tmplDeleteBy = "admin@example.com"

	err := runTmplDelete(nil, []string{fmt.Sprint(7)})
	require.NoError(t, err)
	assert.True(t, rec.deleteHit, "expected DELETE /api/v1/rejection-reason-templates/7 to be called")
}
