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
	requireOneAuditRowBeforeFaultedTx(t, faulty)
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

// The request side of the same contract (#3858): a request whose audit row the audit
// log refuses answers 503 audit_unavailable through sendMFAResetError, and no request
// row is left behind.
func TestRequestMFAReset_AuditOutage_SharedAuditUnavailable503(t *testing.T) {
	w := newMFAResetHandlerWorld(t)
	old := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = old })
	ctx := context.Background()

	// Call 1 is requireReauth's best-effort mfa.reauth_verified row; call 2 is the
	// first row of the request's own transaction.
	faulty := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 2, Kind: faultstorage.KindError, Err: errors.New("injected: audit log refused the row"),
	})
	cs := core.NewKeyorixCore(faulty)
	cs.SetAuthEncryptor(w.enc)
	uh, err := NewUserHandler(cs)
	require.NoError(t, err)
	defaultUserHandler = uh

	rec := w.call(t, w.a, RequestMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests", "",
		fmt.Sprintf(`{"user":"target","reason":"lost phone","verified_by":"video","code":%q}`, w.code(t, w.a.ID)))
	require.True(t, faulty.Fired(), "the request's audit write was never reached")
	requireOneAuditRowBeforeFaultedTx(t, faulty)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, strconv.Itoa(auditUnavailableRetryAfterSeconds), rec.Header().Get("Retry-After"))
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, auditUnavailableCode, body.Error)
	assert.Equal(t, core.MutationAuditUnavailableMessage, body.Message)

	pending, err := w.st.ListMFAResetRequests(ctx, true)
	require.NoError(t, err)
	assert.Empty(t, pending, "a request was recorded although the audit log refused the rows")
}

// requireOneAuditRowBeforeFaultedTx makes the NthCall: 2 assumption explicit. The
// fault counts LogAuditEvent calls, so it only lands on the operation's own first
// audit row if requireReauth wrote exactly one row (outside any transaction) first.
// From the wrapper's call log: exactly one LogAuditEvent precedes the first
// WithTransaction, and the fired record is a LogAuditEvent inside that
// transaction. A change in the reauth row count fails here with this message
// instead of a misleading 503/500 mismatch further down.
func requireOneAuditRowBeforeFaultedTx(t *testing.T, faulty *faultstorage.FaultyStorage) {
	t.Helper()
	var before, firstTx, firedAt int
	firedMethod := ""
	for i, rec := range faulty.Calls() {
		if rec.Method == "WithTransaction" && firstTx == 0 {
			firstTx = i + 1
		}
		if rec.Fired {
			firedAt, firedMethod = i+1, rec.Method
		}
		if rec.Method == "LogAuditEvent" && firstTx == 0 {
			before++
		}
	}
	require.NotZero(t, firstTx, "the operation never opened its transaction; call log: %v", faulty.Calls())
	require.Equal(t, 1, before,
		"NthCall: 2 assumes requireReauth writes exactly one audit row before the operation's transaction; %d were written first (call log: %v)", before, faulty.Calls())
	require.Equal(t, "LogAuditEvent", firedMethod, "the fault fired on %q, not on an audit row (call log: %v)", firedMethod, faulty.Calls())
	require.Greater(t, firedAt, firstTx,
		"the faulted audit row was written before the operation's transaction opened, so it is not the operation's own first row (call log: %v)", faulty.Calls())
}
