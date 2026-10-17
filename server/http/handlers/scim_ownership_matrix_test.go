package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestSCIM_OwnershipMatrix drives EVERY SCIM operation that takes or returns a user
// against every kind of account, and asserts exactly which kinds each operation may
// act on (INV-CORE-scim-ownership-excludes-sso-namespace, #3418). For a refused kind
// it asserts the response is the one a nonexistent id gets (a native id must stay
// indistinguishable from a missing one) and that the account row and its group
// memberships are untouched. TestSCIM_OwnershipMatrixCoversEveryHandler fails when a
// SCIM handler is added without a row here or an explicit exemption.
//
// Account kinds:
//   - native: a local account (no external id).
//   - ssoClaimedNative: a native account claimed by an SSO login through the
//     verified-email fallback. The claim is the storage write resolveSSOUser makes
//     (ClaimUserExternalIDIfUnset with "sso:<provider>:<sub>");
//     internal/core TestSCIM_SSOClaimedNativeAccountIsNotSCIMManaged drives the
//     real resolveSSOUser and pins that form.
//   - scimCreated: created through POST /Users.
//   - scimCreatedSSOLinked: scimCreated, then the same SSO claim attempted; it must
//     not rewrite the SCIM externalId (resolveSSOUser never does for a non-empty id).
func TestSCIM_OwnershipMatrix(t *testing.T) {
	scimKinds := kindSet(kindSCIMCreated, kindSCIMCreatedSSOLinked)
	for _, op := range scimOwnershipOps() {
		for _, kind := range allAccountKinds {
			t.Run(op.name+"/"+string(kind), func(t *testing.T) {
				env := newOwnershipEnv(t)
				acct := env.makeAccount(kind)
				before := env.snapshot(acct.id)

				w := op.run(env, acct)
				allowed := op.allowed(scimKinds)[kind]
				if allowed {
					op.assertAllowed(t, env, acct, w)
					return
				}
				op.assertRefused(t, env, acct, w)
				assert.Equal(t, before, env.snapshot(acct.id),
					"%s on a %s account must not change the account or its memberships", op.name, kind)
			})
		}
	}
}

// scimOwnershipCoveredHandlers / scimOwnershipExempt classify every exported
// *SCIMHandler method. A handler that takes a user id, a user reference or a member
// list must be in the matrix; the exemptions say why each one is not.
var scimOwnershipExempt = map[string]string{
	"GetServiceProviderConfig": "static capability document; no account input or output",
	"ListGroups":               "group read; takes no user id. NOT ownership-gated: it renders every member's id and email, native members included (follow-up in the SCIM-HARDEN-1 report)",
	"GetGroup":                 "group read; takes no user id. NOT ownership-gated: same member rendering as ListGroups",
	"DeleteGroup":              "removes a group, never a user; guarded by the last-admin group guard (SCIM-5)",
}

func TestSCIM_OwnershipMatrixCoversEveryHandler(t *testing.T) {
	covered := map[string]bool{}
	for _, op := range scimOwnershipOps() {
		covered[op.handler] = true
	}
	typ := reflect.TypeFor[*SCIMHandler]()
	var missing []string
	for m := range typ.Methods() {
		name := m.Name
		if covered[name] {
			continue
		}
		if _, ok := scimOwnershipExempt[name]; ok {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	require.Empty(t, missing, "SCIM handler(s) with no ownership-matrix row and no exemption: add an op to scimOwnershipOps (or an exemption with its reason)")
	for name := range scimOwnershipExempt {
		_, ok := typ.MethodByName(name)
		require.True(t, ok, "stale exemption %q: no such SCIMHandler method", name)
	}
}

type accountKind string

const (
	kindNative               accountKind = "native"
	kindSSOClaimedNative     accountKind = "ssoClaimedNative"
	kindSCIMCreated          accountKind = "scimCreated"
	kindSCIMCreatedSSOLinked accountKind = "scimCreatedSSOLinked"
)

var allAccountKinds = []accountKind{kindNative, kindSSOClaimedNative, kindSCIMCreated, kindSCIMCreatedSSOLinked}

func kindSet(ks ...accountKind) map[accountKind]bool {
	m := map[accountKind]bool{}
	for _, k := range ks {
		m[k] = true
	}
	return m
}

const ownershipMissingID = 4242

type ownershipEnv struct {
	t      *testing.T
	h      *SCIMHandler
	db     *gorm.DB
	ls     *store.LocalStorage
	groups int
}

type ownershipAccount struct {
	id    uint
	email string
}

func newOwnershipEnv(t *testing.T) *ownershipEnv {
	t.Helper()
	h, db := setupSCIMTest(t)
	return &ownershipEnv{t: t, h: h, db: db, ls: store.NewLocalStorage(db)}
}

func (e *ownershipEnv) makeAccount(kind accountKind) ownershipAccount {
	e.t.Helper()
	const email = "acct@corp.com"
	ctx := context.Background()
	var id uint
	switch kind {
	case kindNative, kindSSOClaimedNative:
		u := &models.User{Username: "acct", UsernameFolded: "acct", Email: email, EmailFolded: email,
			DisplayName: "Acct", IsActive: true, AccountState: "active"}
		require.NoError(e.t, e.db.Create(u).Error)
		id = u.ID
	case kindSCIMCreated, kindSCIMCreatedSSOLinked:
		w := e.do(http.MethodPost, "/scim/v2/Users", "",
			`{"userName":"`+email+`","externalId":"00u-acct","displayName":"Acct","active":true}`, e.h.CreateUser)
		require.Equal(e.t, http.StatusCreated, w.Code, w.Body.String())
		n, err := strconv.ParseUint(decodeSCIM(e.t, w)["id"].(string), 10, 32)
		require.NoError(e.t, err)
		id = uint(n)
		// Make it login-capable like a native account, so a refused deactivation
		// is observable on the same columns.
		require.NoError(e.t, e.db.Model(&models.User{}).Where("id = ?", id).Update("account_state", "active").Error)
	}
	if kind == kindSSOClaimedNative || kind == kindSCIMCreatedSSOLinked {
		claimed, err := e.ls.ClaimUserExternalIDIfUnset(ctx, id, "sso:okta:sub-acct", time.Now())
		require.NoError(e.t, err)
		require.Equal(e.t, kind == kindSSOClaimedNative, claimed,
			"the SSO claim lands on an unfederated account and never on a SCIM-created one")
	}
	return ownershipAccount{id: id, email: email}
}

type ownershipSnapshot struct {
	Email, DisplayName, AccountState, ExternalID string
	IsActive, Deleted                            bool
	Groups                                       int64
}

func (e *ownershipEnv) snapshot(id uint) ownershipSnapshot {
	e.t.Helper()
	var u models.User
	require.NoError(e.t, e.db.Unscoped().First(&u, id).Error)
	var groups int64
	require.NoError(e.t, e.db.Model(&models.UserGroup{}).Where("user_id = ?", id).Count(&groups).Error)
	return ownershipSnapshot{Email: u.Email, DisplayName: u.DisplayName, AccountState: u.AccountState,
		ExternalID: u.ExternalID, IsActive: u.IsActive, Deleted: u.DeletedAt.Valid, Groups: groups}
}

func (e *ownershipEnv) do(method, target, id, body string, fn http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
	if id != "" {
		req = withID(req, id)
	}
	w := httptest.NewRecorder()
	fn(w, req)
	return w
}

// makeGroup creates an empty SCIM group and returns its id.
func (e *ownershipEnv) makeGroup() string {
	e.t.Helper()
	e.groups++
	w := e.do(http.MethodPost, "/scim/v2/Groups", "", fmt.Sprintf(`{"displayName":"grp%d"}`, e.groups), e.h.CreateGroup)
	require.Equal(e.t, http.StatusCreated, w.Code, w.Body.String())
	return decodeSCIM(e.t, w)["id"].(string)
}

type scimOwnershipOp struct {
	name    string
	handler string // the *SCIMHandler method this row covers
	run     func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder
	// missing runs the same operation against a nonexistent account; a refused
	// kind must get exactly this response.
	missing       func(e *ownershipEnv) *httptest.ResponseRecorder
	allowed       func(scimKinds map[accountKind]bool) map[accountKind]bool
	assertAllowed func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder)
	// refusedCheck overrides the default "same response as a missing id" check.
	refusedCheck func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder)
}

func (op scimOwnershipOp) assertRefused(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
	t.Helper()
	if op.refusedCheck != nil {
		op.refusedCheck(t, e, a, w)
		return
	}
	ref := op.missing(e)
	assert.Equal(t, ref.Code, w.Code, "a refused account must answer like a missing one (status); body=%s", w.Body.String())
	assert.Equal(t, ref.Body.String(), w.Body.String(), "a refused account must answer like a missing one (body)")
}

func onlySCIM(scimKinds map[accountKind]bool) map[accountKind]bool { return scimKinds }
func nobody(map[accountKind]bool) map[accountKind]bool             { return map[accountKind]bool{} }

func idStr(id uint) string { return strconv.FormatUint(uint64(id), 10) }

func groupMemberBody(name string, id string) string {
	return `{"displayName":"` + name + `","members":[{"value":"` + id + `"}]}`
}

func scimOwnershipOps() []scimOwnershipOp {
	userPath := func(id string) string { return "/scim/v2/Users/" + id }
	putBody := `{"userName":"x","displayName":"Rewritten","emails":[{"value":"attacker@corp.com","primary":true}],"active":true}`
	patchOff := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	filterTarget := func(email string) string {
		return "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "`+email+`"`)
	}
	groupStatus := func(want int) func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
		return func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
			assert.Equal(t, want, w.Code, w.Body.String())
			assert.Equal(t, int64(1), e.snapshot(a.id).Groups, "a SCIM-managed member must be added")
		}
	}
	// A refused member is reported with its id, so compare status and the body with
	// the id normalised against a nonexistent member.
	groupRefused := func(run func(e *ownershipEnv, id string) *httptest.ResponseRecorder) func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
		return func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
			ref := run(e, idStr(ownershipMissingID))
			assert.Equal(t, ref.Code, w.Code, "a refused member must answer like a missing one (status); body=%s", w.Body.String())
			assert.Equal(t, ref.Body.String(),
				string(bytes.ReplaceAll(w.Body.Bytes(), []byte(idStr(a.id)), []byte(idStr(ownershipMissingID)))),
				"a refused member must answer like a missing one (body)")
		}
	}
	groupCreate := func(e *ownershipEnv, id string) *httptest.ResponseRecorder {
		return e.do(http.MethodPost, "/scim/v2/Groups", "", groupMemberBody("eng-"+id, id), e.h.CreateGroup)
	}
	groupReplace := func(e *ownershipEnv, id string) *httptest.ResponseRecorder {
		gid := e.makeGroup()
		return e.do(http.MethodPut, "/scim/v2/Groups/"+gid, gid, groupMemberBody("grp-replaced-"+id, id), e.h.ReplaceGroup)
	}
	groupPatchAdd := func(e *ownershipEnv, id string) *httptest.ResponseRecorder {
		gid := e.makeGroup()
		body := `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + id + `"}]}]}`
		return e.do(http.MethodPatch, "/scim/v2/Groups/"+gid, gid, body, e.h.PatchGroup)
	}

	return []scimOwnershipOp{
		{
			name: "get", handler: "GetUser", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodGet, userPath(idStr(a.id)), idStr(a.id), "", e.h.GetUser)
			},
			missing: func(e *ownershipEnv) *httptest.ResponseRecorder {
				return e.do(http.MethodGet, userPath(idStr(ownershipMissingID)), idStr(ownershipMissingID), "", e.h.GetUser)
			},
			assertAllowed: func(t *testing.T, _ *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				assert.Equal(t, idStr(a.id), decodeSCIM(t, w)["id"])
			},
		},
		{
			name: "listFilter", handler: "ListUsers", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodGet, filterTarget(a.email), "", "", e.h.ListUsers)
			},
			missing: func(e *ownershipEnv) *httptest.ResponseRecorder {
				return e.do(http.MethodGet, filterTarget("nobody@corp.com"), "", "", e.h.ListUsers)
			},
			assertAllowed: func(t *testing.T, _ *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				res := decodeSCIM(t, w)["Resources"].([]any)
				require.Len(t, res, 1)
				assert.Equal(t, idStr(a.id), res[0].(map[string]any)["id"])
			},
		},
		{
			name: "listPage", handler: "ListUsers", allowed: onlySCIM,
			run: func(e *ownershipEnv, _ ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodGet, "/scim/v2/Users", "", "", e.h.ListUsers)
			},
			assertAllowed: func(t *testing.T, _ *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				body := decodeSCIM(t, w)
				assert.EqualValues(t, 1, body["totalResults"])
				res := body["Resources"].([]any)
				require.Len(t, res, 1)
				assert.Equal(t, idStr(a.id), res[0].(map[string]any)["id"])
			},
			refusedCheck: func(t *testing.T, _ *ownershipEnv, _ ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				body := decodeSCIM(t, w)
				assert.EqualValues(t, 0, body["totalResults"], "the list must not count a non-SCIM account")
				assert.Empty(t, body["Resources"])
			},
		},
		{
			// A create whose userName/email is already taken never adopts or touches
			// the existing account, whatever its kind.
			name: "createCollision", handler: "CreateUser", allowed: nobody,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodPost, "/scim/v2/Users", "",
					`{"userName":"`+a.email+`","externalId":"00u-other","active":false}`, e.h.CreateUser)
			},
			refusedCheck: func(t *testing.T, e *ownershipEnv, _ ownershipAccount, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
				var n int64
				require.NoError(t, e.db.Model(&models.User{}).Count(&n).Error)
				assert.Equal(t, int64(1), n, "no second account may be created")
			},
		},
		{
			name: "replace", handler: "ReplaceUser", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodPut, userPath(idStr(a.id)), idStr(a.id), putBody, e.h.ReplaceUser)
			},
			missing: func(e *ownershipEnv) *httptest.ResponseRecorder {
				return e.do(http.MethodPut, userPath(idStr(ownershipMissingID)), idStr(ownershipMissingID), putBody, e.h.ReplaceUser)
			},
			assertAllowed: func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				assert.Equal(t, "attacker@corp.com", e.snapshot(a.id).Email)
			},
		},
		{
			name: "patchDeactivate", handler: "PatchUser", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodPatch, userPath(idStr(a.id)), idStr(a.id), patchOff, e.h.PatchUser)
			},
			missing: func(e *ownershipEnv) *httptest.ResponseRecorder {
				return e.do(http.MethodPatch, userPath(idStr(ownershipMissingID)), idStr(ownershipMissingID), patchOff, e.h.PatchUser)
			},
			assertAllowed: func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				assert.False(t, e.snapshot(a.id).IsActive)
			},
		},
		{
			name: "deprovision", handler: "DeleteUser", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return e.do(http.MethodDelete, userPath(idStr(a.id)), idStr(a.id), "", e.h.DeleteUser)
			},
			missing: func(e *ownershipEnv) *httptest.ResponseRecorder {
				return e.do(http.MethodDelete, userPath(idStr(ownershipMissingID)), idStr(ownershipMissingID), "", e.h.DeleteUser)
			},
			assertAllowed: func(t *testing.T, e *ownershipEnv, a ownershipAccount, w *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
				assert.True(t, e.snapshot(a.id).Deleted)
			},
		},
		{
			name: "groupCreateMember", handler: "CreateGroup", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return groupCreate(e, idStr(a.id))
			},
			assertAllowed: groupStatus(http.StatusCreated),
			refusedCheck:  groupRefused(groupCreate),
		},
		{
			name: "groupReplaceMember", handler: "ReplaceGroup", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return groupReplace(e, idStr(a.id))
			},
			assertAllowed: groupStatus(http.StatusOK),
			refusedCheck:  groupRefused(groupReplace),
		},
		{
			name: "groupPatchAddMember", handler: "PatchGroup", allowed: onlySCIM,
			run: func(e *ownershipEnv, a ownershipAccount) *httptest.ResponseRecorder {
				return groupPatchAdd(e, idStr(a.id))
			},
			assertAllowed: groupStatus(http.StatusOK),
			refusedCheck:  groupRefused(groupPatchAdd),
		},
	}
}
