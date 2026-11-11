package handlers

// IDENTITY-INPUT-BOUNDS-1 item 1: a SCIM `active` sent as a string (Microsoft Entra
// ID: {"op":"Replace","path":"active","value":"False"}) used to fail a strict bool
// unmarshal, leave active nil and answer 200 with nothing changed: the terminated
// user stayed active with its PATs live. These tests assert the EFFECT, read back
// from storage (the user row and its PAT rows), not the handler's return value.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// provisionSCIMUserWithPAT provisions an active SCIM user through the handler and
// gives it one live PAT row. It returns the SCIM id and the stored user id.
func provisionSCIMUserWithPAT(t *testing.T, h *SCIMHandler, db *gorm.DB, email string) (string, uint) {
	t.Helper()
	body := `{"userName":"` + email + `","externalId":"ext-` + email + `","active":true}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	id, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, id)
	var u models.User
	require.NoError(t, db.Where("email = ?", email).First(&u).Error)
	require.True(t, u.IsActive, "fixture: provisioned user starts active")
	require.NoError(t, db.Create(&models.PersonalAccessToken{UserID: u.ID, Name: "ci", TokenHash: "hash-" + email, TokenPrefix: "kx_pat_x"}).Error)
	return id, u.ID
}

func patchSCIM(h *SCIMHandler, id, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+id, bytes.NewReader([]byte(body))), id))
	return w
}

func storedUser(t *testing.T, db *gorm.DB, uid uint) models.User {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, uid).Error)
	return u
}

func livePATCount(t *testing.T, db *gorm.DB, uid uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.PersonalAccessToken{}).Where("user_id = ? AND revoked = ?", uid, false).Count(&n).Error)
	return n
}

// TestSCIM_PatchActiveStringDeactivates covers the Entra shapes: the string value in
// any case, a capitalised op name, and the path-less object form. Each one must
// actually deactivate the stored user and revoke its PAT.
func TestSCIM_PatchActiveStringDeactivates(t *testing.T) {
	cases := map[string]string{
		"entra path form":         `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`,
		"lower-case string":       `{"Operations":[{"op":"replace","path":"active","value":"false"}]}`,
		"upper-case op and value": `{"Operations":[{"op":"REPLACE","path":"Active","value":"FALSE"}]}`,
		"capitalised Add":         `{"Operations":[{"op":"Add","path":"active","value":"False"}]}`,
		"path-less object string": `{"Operations":[{"op":"Replace","value":{"active":"False"}}]}`,
		"path-less key case":      `{"Operations":[{"op":"Replace","value":{"Active":"False","displayName":"Gone"}}]}`,
		"path-less JSON bool":     `{"Operations":[{"op":"Replace","value":{"active":false}}]}`,
	}
	n := 0
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h, db := setupSCIMTest(t)
			n++
			id, uid := provisionSCIMUserWithPAT(t, h, db, "entra"+string(rune('a'+n))+"@corp.com")

			w := patchSCIM(h, id, body)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())

			assert.False(t, storedUser(t, db, uid).IsActive, "stored user must be deactivated")
			assert.Zero(t, livePATCount(t, db, uid), "the user's PATs must be revoked")
		})
	}
}

// TestSCIM_PatchActiveStringTrueReactivates: "True" reactivates a deactivated user.
func TestSCIM_PatchActiveStringTrueReactivates(t *testing.T) {
	h, db := setupSCIMTest(t)
	id, uid := provisionSCIMUserWithPAT(t, h, db, "reactivate@corp.com")
	require.Equal(t, http.StatusOK, patchSCIM(h, id, `{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`).Code)
	require.False(t, storedUser(t, db, uid).IsActive)

	w := patchSCIM(h, id, `{"Operations":[{"op":"Replace","path":"active","value":"True"}]}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, storedUser(t, db, uid).IsActive, "stored user must be reactivated")
}

// TestSCIM_PatchActiveGarbageIs400 — an `active` that is present but not a boolean is
// a 400 invalidValue and changes nothing; it never answers 200.
func TestSCIM_PatchActiveGarbageIs400(t *testing.T) {
	cases := map[string]string{
		"word":             `{"Operations":[{"op":"Replace","path":"active","value":"no"}]}`,
		"number":           `{"Operations":[{"op":"Replace","path":"active","value":0}]}`,
		"null":             `{"Operations":[{"op":"Replace","path":"active","value":null}]}`,
		"missing value":    `{"Operations":[{"op":"Replace","path":"active"}]}`,
		"object":           `{"Operations":[{"op":"Replace","path":"active","value":{"x":1}}]}`,
		"path-less word":   `{"Operations":[{"op":"Replace","value":{"active":"disabled"}}]}`,
		"path-less null":   `{"Operations":[{"op":"Replace","value":{"active":null}}]}`,
		"after a good one": `{"Operations":[{"op":"Replace","path":"displayName","value":"X"},{"op":"Replace","path":"active","value":"nope"}]}`,
	}
	n := 0
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h, db := setupSCIMTest(t)
			n++
			id, uid := provisionSCIMUserWithPAT(t, h, db, "garbage"+string(rune('a'+n))+"@corp.com")
			before := storedUser(t, db, uid)

			w := patchSCIM(h, id, body)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, "invalidValue", decodeSCIM(t, w)["scimType"])

			after := storedUser(t, db, uid)
			assert.True(t, after.IsActive, "a refused patch changes nothing")
			assert.Equal(t, before.DisplayName, after.DisplayName, "a refused patch applies no other operation")
			assert.Equal(t, int64(1), livePATCount(t, db, uid))
		})
	}
}

// TestSCIM_PatchUnknownPathStillIgnored keeps the documented tolerance: a path that is
// not `active` is a no-op, whatever its value.
func TestSCIM_PatchUnknownPathStillIgnored(t *testing.T) {
	h, db := setupSCIMTest(t)
	id, uid := provisionSCIMUserWithPAT(t, h, db, "unknownpath@corp.com")
	w := patchSCIM(h, id, `{"Operations":[{"op":"Replace","path":"title","value":"False"},{"op":"Replace","value":{"nickName":"x","active":true}}]}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, storedUser(t, db, uid).IsActive)
}

// TestSCIM_PutActiveString: PUT carries the same tolerant `active`, and a garbage one
// is 400 invalidValue, not a 200 that ignores it.
func TestSCIM_PutActiveString(t *testing.T) {
	h, db := setupSCIMTest(t)
	id, uid := provisionSCIMUserWithPAT(t, h, db, "put@corp.com")
	put := func(active string) *httptest.ResponseRecorder {
		body := `{"userName":"put@corp.com","emails":[{"value":"put@corp.com","primary":true}],"active":` + active + `}`
		w := httptest.NewRecorder()
		h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+id, bytes.NewReader([]byte(body))), id))
		return w
	}

	w := put(`"maybe"`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Equal(t, "invalidValue", decodeSCIM(t, w)["scimType"])
	require.True(t, storedUser(t, db, uid).IsActive)

	w = put(`null`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = put(`"False"`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.False(t, storedUser(t, db, uid).IsActive, "PUT active \"False\" deactivates")
	assert.Zero(t, livePATCount(t, db, uid))
}

// TestSCIM_PostActiveString: POST provisions inactive for "False" and refuses garbage.
func TestSCIM_PostActiveString(t *testing.T) {
	h, db := setupSCIMTest(t)
	post := func(email, active string) *httptest.ResponseRecorder {
		body := `{"userName":"` + email + `","externalId":"ext-` + email + `","active":` + active + `}`
		w := httptest.NewRecorder()
		h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
		return w
	}

	w := post("garbagepost@corp.com", `"off"`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Equal(t, "invalidValue", decodeSCIM(t, w)["scimType"])
	var n int64
	require.NoError(t, db.Model(&models.User{}).Where("email = ?", "garbagepost@corp.com").Count(&n).Error)
	assert.Zero(t, n, "a refused POST provisions nothing")

	w = post("inactivepost@corp.com", `"False"`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, false, decodeSCIM(t, w)["active"])
	// ProvisionSCIMUser marks an inactive provision by account state (IsActive's
	// gorm default:true swallows a false zero value on create), so read that.
	var u models.User
	require.NoError(t, db.Where("email = ?", "inactivepost@corp.com").First(&u).Error)
	assert.Equal(t, core.AccountDeprovisioned, u.AccountState, "POST active \"False\" provisions a login-blocked user")
	assert.True(t, core.AccountLoginBlocked(u.ID, u.AccountState))
}

func TestParseSCIMBool(t *testing.T) {
	for in, want := range map[string]bool{`true`: true, `false`: false, ` true `: true, `"True"`: true, `"FALSE"`: false, `" false "`: false} {
		got, err := parseSCIMBool([]byte(in))
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{``, `null`, `1`, `0`, `"yes"`, `"t"`, `"1"`, `[]`, `{}`, `"true`, `tru`} {
		_, err := parseSCIMBool([]byte(in))
		assert.ErrorIs(t, err, errSCIMInvalidBool, in)
	}
}
