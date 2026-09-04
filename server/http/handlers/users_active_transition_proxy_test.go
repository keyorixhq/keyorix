// users_active_transition_proxy_test.go — tests for
// users_active_transition_proxy.go: UpdateUserIfActiveStateMatchesProxy.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateUserIfActiveStateMatchesProxy_BadID — non-numeric id → 400.
func TestUpdateUserIfActiveStateMatchesProxy_BadID(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/bad/active-transition", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestUpdateUserIfActiveStateMatchesProxy_BadBody — malformed JSON → 400.
func TestUpdateUserIfActiveStateMatchesProxy_BadBody(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestUpdateUserIfActiveStateMatchesProxy_HappyPath — a conditional write
// against a non-admin user (IsActive=true) with a matching from_active
// succeeds and reports matched:true.
//
// G80: deliberately NOT the seeded admin (id=1) any more -- this route now
// calls core.GuardLastAdminDeactivation, which correctly refuses to deactivate
// the install's only admin. Using a non-admin user keeps this test's actual
// subject (the conditional-write/CAS mechanics) isolated from that guard,
// which has its own dedicated tests
// (users_active_transition_proxy_lastadmin_test.go).
func TestUpdateUserIfActiveStateMatchesProxy_HappyPath(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	target := &models.User{Username: "s12nonadmin-happy", Email: "s12nonadmin-happy@example.com", AccountState: "active"}
	require.NoError(t, db.Create(target).Error)
	idStr := machineUintToStr(target.ID)

	body := proxyJSON(map[string]interface{}{
		"username":     target.Username,
		"email":        target.Email,
		"display_name": "Deactivated User",
		"active":       false,
		"from_active":  true,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/"+idStr+"/active-transition", body),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["matched"])

	updated, err := cs.Storage().GetUser(req.Context(), target.ID)
	require.NoError(t, err)
	assert.False(t, updated.IsActive)
	assert.Equal(t, "Deactivated User", updated.DisplayName)
}

// TestUpdateUserIfActiveStateMatchesProxy_LostRace — a second conditional
// write asserting the SAME (now-stale) from_active as a call that already won
// must report matched:false, not silently re-apply over the winner (proves
// the CAS race is closed at the HTTP-proxy boundary too, not just LocalStorage).
// G80: uses a non-admin user, same reasoning as the HappyPath test above.
func TestUpdateUserIfActiveStateMatchesProxy_LostRace(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	target := &models.User{Username: "s12nonadmin-race", Email: "s12nonadmin-race@example.com", AccountState: "active"}
	require.NoError(t, db.Create(target).Error)
	idStr := machineUintToStr(target.ID)

	firstBody := proxyJSON(map[string]interface{}{
		"username":     target.Username,
		"email":        target.Email,
		"display_name": "First Winner",
		"active":       false,
		"from_active":  true,
	})
	firstReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/"+idStr+"/active-transition", firstBody),
		"id", idStr,
	)
	w1 := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w1, firstReq)
	assert.Equal(t, http.StatusOK, w1.Code)
	resp1 := decodeRemoteResp(t, w1)
	data1, ok := resp1.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data1["matched"], "first call must win")

	// Second call still asserts from_active=true (stale — the row is now false).
	secondBody := proxyJSON(map[string]interface{}{
		"username":     target.Username,
		"email":        target.Email,
		"display_name": "Should Not Persist",
		"active":       false,
		"from_active":  true,
	})
	secondReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/"+idStr+"/active-transition", secondBody),
		"id", idStr,
	)
	w2 := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w2, secondReq)
	assert.Equal(t, http.StatusOK, w2.Code)
	resp2 := decodeRemoteResp(t, w2)
	data2, ok := resp2.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, data2["matched"], "second (racing) call must lose")

	updated, err := cs.Storage().GetUser(secondReq.Context(), target.ID)
	require.NoError(t, err)
	assert.NotEqual(t, "Should Not Persist", updated.DisplayName)
}

// TestUpdateUserIfActiveStateMatchesProxy_DuplicateEmail — a conditional
// write whose email collides with a different existing user hits the
// partial unique index and returns a client error, not a silent success.
// Exercises LocalStorage.UpdateUserIfActiveStateMatches's error-translation
// branch (internal/storage/store/local_users.go) and this handler's
// error-mapping code, including (when the driver error text matches) the
// errors.Is(err, storage.ErrDuplicateEmail) -> 409 DUPLICATE_EMAIL path.
//
// Doesn't assert the specific 409/DUPLICATE_EMAIL outcome: per this
// codebase's own established convention (see
// internal/storage/store/store_max_test.go's TestCreateUser_
// DuplicateEmailSentinel comment), the sentinel only reliably propagates
// when the partial index NAME appears in the driver error text, which
// SQLite doesn't guarantee on every constraint-violation shape (an UPDATE
// hitting the index can surface as a bare "UNIQUE constraint failed:
// users.email" instead) -- only Postgres includes it reliably. Either
// outcome here (409 DUPLICATE_EMAIL, or 500 STORAGE_ERROR) proves the
// request was correctly rejected rather than silently persisted.
func TestUpdateUserIfActiveStateMatchesProxy_DuplicateEmail(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// Replicate the partial unique index migrateDatabase creates in
	// production (see internal/storage/store/store_max_test.go's
	// newUserStoreMax for the identical pattern) -- SQLite surfaces it in
	// the error message, which isDuplicateEmailViolation matches on.
	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users(email) WHERE deleted_at IS NULL AND email != ''")

	require.NoError(t, db.Create(&models.User{
		ID: 2, Username: "other_user", UsernameFolded: "other_user", Email: "taken@example.com", EmailFolded: "taken@example.com", IsActive: true,
	}).Error)

	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	body := proxyJSON(map[string]interface{}{
		"username":     "testuser_s12",
		"email":        "taken@example.com", // collides with user 2
		"display_name": "Should Not Persist",
		"active":       false,
		"from_active":  true,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success, "duplicate email must not silently succeed")
	if w.Code == http.StatusConflict {
		assert.Equal(t, duplicateEmailProxyCode, resp.Error.Code)
	} else {
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "STORAGE_ERROR", resp.Error.Code)
	}

	unchanged, err := cs.Storage().GetUser(req.Context(), 1)
	require.NoError(t, err)
	assert.NotEqual(t, "Should Not Persist", unchanged.DisplayName, "rejected write must not persist")
}

// TestUpdateUserIfActiveStateMatchesProxy_PreservesPasswordHashAndAccountState
// is the containment fix's own regression test: this route used to build a
// caller-controlled *models.User with every field this route's wire body
// doesn't carry left at Go's zero value, then persist it via a Select("*")
// full-row overwrite -- silently blanking PasswordHash and AccountState on
// EVERY successful call, not just a malicious one (RemoteStorage's client
// never sends either field to begin with: PasswordHash is json:"-" and never
// crosses the wire, and account_state has no field in this route's wire
// format at all). Blanking AccountState on a suspended/deprovisioned account
// is a fail-open authentication bypass (AccountLoginBlocked treats an
// unrecognized/empty state as NOT blocked) -- this test proves the fetch-first
// fix closes it: a real password hash and a non-active account state survive
// a legitimate, successful call to this route completely unchanged.
func TestUpdateUserIfActiveStateMatchesProxy_PreservesPasswordHashAndAccountState(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	target := &models.User{
		Username: "s12nonadmin-hashcheck", Email: "s12nonadmin-hashcheck@example.com",
		PasswordHash: "REAL_BCRYPT_HASH_MUST_SURVIVE", AccountState: "suspended", IsActive: true,
	}
	require.NoError(t, db.Create(target).Error)
	idStr := machineUintToStr(target.ID)

	body := proxyJSON(map[string]interface{}{
		"username":     target.Username,
		"email":        target.Email,
		"display_name": "Updated Name",
		"active":       true,
		"from_active":  true,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/"+idStr+"/active-transition", body),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	require.True(t, resp.Success)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, true, data["matched"], "the call itself must have succeeded for this test to prove anything")

	updated, err := cs.Storage().GetUser(req.Context(), target.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.DisplayName, "the legitimately-carried field DID change")
	assert.Equal(t, "REAL_BCRYPT_HASH_MUST_SURVIVE", updated.PasswordHash,
		"PasswordHash must survive a call to this route unchanged")
	assert.Equal(t, "suspended", updated.AccountState,
		"AccountState must survive a call to this route unchanged")
}

// TestUpdateUserIfActiveStateMatchesProxy_MismatchLeavesRowCompletelyUnchanged
// re-verifies, for this route, the same mutate-before-checking ordering bug
// caught in the WebAuthn authz fix: a from_active precondition mismatch must
// leave the ENTIRE row untouched, not just fail to apply the intended
// transition. Because the fix fetches first and the storage layer's own
// WHERE-gated Updates() either matches the row (and writes it) or matches zero
// rows (and writes nothing) as a single atomic operation, there is no window
// where a partial write could land -- this test proves that empirically,
// including for the fields the earlier bug used to zero.
func TestUpdateUserIfActiveStateMatchesProxy_MismatchLeavesRowCompletelyUnchanged(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	target := &models.User{
		Username: "s12nonadmin-mismatch", Email: "s12nonadmin-mismatch@example.com",
		PasswordHash: "UNCHANGED_HASH", AccountState: "active", IsActive: true,
		DisplayName: "Original Name",
	}
	require.NoError(t, db.Create(target).Error)
	idStr := machineUintToStr(target.ID)

	// from_active asserts false, but the row is actually true -- a stale/wrong
	// precondition, matching the LostRace test's own shape.
	body := proxyJSON(map[string]interface{}{
		"username":     target.Username,
		"email":        target.Email,
		"display_name": "Should Not Persist",
		"active":       false,
		"from_active":  false,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/"+idStr+"/active-transition", body),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, false, data["matched"], "the precondition mismatch must be reported")

	unchanged, err := cs.Storage().GetUser(req.Context(), target.ID)
	require.NoError(t, err)
	assert.Equal(t, "Original Name", unchanged.DisplayName, "no field may change on a rejected precondition")
	assert.Equal(t, "UNCHANGED_HASH", unchanged.PasswordHash)
	assert.Equal(t, "active", unchanged.AccountState)
	assert.True(t, unchanged.IsActive)
}

// TestUpdateUserIfActiveStateMatchesProxy_RejectsUnknownField proves a body
// carrying a field this route doesn't declare -- e.g. an attempt to smuggle
// password_hash or account_state through it -- is rejected outright (400),
// not silently ignored.
func TestUpdateUserIfActiveStateMatchesProxy_RejectsUnknownField(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition",
			strings.NewReader(`{"username":"x","email":"x@y.com","display_name":"x","active":true,`+
				`"from_active":true,"password_hash":"sneaky"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestUpdateUserIfActiveStateMatchesProxy_DuplicateUsername is the #G79
// regression: this proxy previously ran no uniqueness pre-check at all
// (unlike core.UpdateUser, which checks GetUserByUsername/GetUserByEmail
// before persisting) — a username collision is now refused explicitly with
// duplicateUsernameProxyCode rather than falling through to whatever the
// storage layer's own constraint (if any) happens to surface.
func TestUpdateUserIfActiveStateMatchesProxy_DuplicateUsername(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.User{
		ID: 2, Username: "taken_username", UsernameFolded: "taken_username", Email: "user2@example.com", EmailFolded: "user2@example.com", IsActive: true,
	}).Error)

	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	body := proxyJSON(map[string]interface{}{
		"username":     "taken_username", // collides with user 2
		"email":        "testuser_s12@example.com",
		"display_name": "Should Not Persist",
		"active":       false,
		"from_active":  true,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success, "duplicate username must not silently succeed")
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, duplicateUsernameProxyCode, resp.Error.Code)

	unchanged, err := cs.Storage().GetUser(req.Context(), 1)
	require.NoError(t, err)
	assert.NotEqual(t, "Should Not Persist", unchanged.DisplayName, "rejected write must not persist")
}
