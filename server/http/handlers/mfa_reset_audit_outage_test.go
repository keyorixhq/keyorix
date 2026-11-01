package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MFA-RESET-TAILS-2 item 3 (REVIEW-3838-DEEP-1 L3): an approval whose audit rows the
// audit log refuses answers like every other audited mutation (sendAuditUnavailable:
// 503, Retry-After, error code audit_unavailable and the fixed message), not with a
// body of its own, and the reset is not applied.
func TestApproveMFAReset_AuditOutage_SharedAuditUnavailable503(t *testing.T) {
	w := newMFAResetHandlerWorld(t)
	old := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = old })
	uh, err := NewUserHandler(w.cs)
	require.NoError(t, err)
	defaultUserHandler = uh
	ctx := context.Background()

	rec := w.call(t, w.a, RequestMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests", "",
		fmt.Sprintf(`{"user":"target","reason":"lost phone","verified_by":"video","code":%q}`, w.code(t, w.a.ID)))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	pending, err := w.st.ListMFAResetRequests(ctx, true)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	id := strconv.FormatUint(uint64(pending[0].ID), 10)

	// Call 1 is requireReauth's best-effort mfa.reauth_verified row; call 2 is the
	// first row of the approval's own transaction (as in core's
	// TestMFAReset_AuditWriteRefused_NothingChanges).
	faulty := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 2, Kind: faultstorage.KindError, Err: errors.New("injected: audit log refused the row"),
	})
	cs := core.NewKeyorixCore(faulty)
	cs.SetAuthEncryptor(w.enc)
	uh, err = NewUserHandler(cs)
	require.NoError(t, err)
	defaultUserHandler = uh

	rec = w.call(t, w.b, ApproveMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests/"+id+"/approve", id,
		fmt.Sprintf(`{"code":%q}`, w.code(t, w.b.ID)))
	require.True(t, faulty.Fired(), "the approval's audit write was never reached")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, strconv.Itoa(auditUnavailableRetryAfterSeconds), rec.Header().Get("Retry-After"))
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, auditUnavailableCode, body.Error)
	assert.Equal(t, core.MutationAuditUnavailableMessage, body.Message)
	assert.NotContains(t, rec.Body.String(), "one_time_password")

	u, err := w.st.GetUser(ctx, w.target.ID)
	require.NoError(t, err)
	assert.True(t, u.MFAEnabled, "the target's factor was reset although the audit log refused the rows")
	assert.False(t, u.MFAEnrolmentRequired)
	r, err := w.st.GetMFAResetRequest(ctx, pending[0].ID)
	require.NoError(t, err)
	assert.Equal(t, models.MFAResetStatusPending, r.Status)
}
