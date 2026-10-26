package handlers

// #3620 (SCIM-NOTIFY-1): the SCIM Group endpoints must tell an IdP the truth about a
// failed write, like the User endpoints do since #3494. GetGroup/ReplaceGroup/
// PatchGroup/DeleteGroup answered every error with 404 and CreateGroup with 400. An
// IdP never retries either, so a change a storage failure rolled back was lost for
// good (a member removal that did not happen, a group delete that did not happen).
//
// These tests inject storage faults under the real core with the faultstorage wrapper,
// for each of the five handlers, and pin the status per class:
//
//   - any storage failure (transient, deadlock, rolled back, canceled) -> 500, generic
//     detail, the real error in the server log, and nothing changed;
//   - a real not-found is still 404 (scim_group_not_found_test.go);
//   - a duplicate group name is 409 "uniqueness"; a non-SCIM-managed member is 400
//     "invalidValue"; a group that confers admin is a permanent 403.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func scimGroupDo(h http.HandlerFunc, method, id, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	path := "/scim/v2/Groups"
	if id != "" {
		path += "/" + id
	}
	r := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	if id != "" {
		r = withID(r, id)
	}
	h(w, r)
	return w
}

// provisionGroup creates a SCIM group with the given members and returns its id.
func provisionGroup(t *testing.T, h *SCIMHandler, name string, members ...string) string {
	t.Helper()
	ms := ""
	for i, m := range members {
		if i > 0 {
			ms += ","
		}
		ms += `{"value":"` + m + `"}`
	}
	w := scimGroupDo(h.CreateGroup, http.MethodPost, "", `{"displayName":"`+name+`","members":[`+ms+`]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	id, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, id)
	return id
}

func scimGroupState(t *testing.T, db *gorm.DB, id string) (name string, live bool, members int64) {
	t.Helper()
	var g models.Group
	require.NoError(t, db.Unscoped().First(&g, id).Error)
	require.NoError(t, db.Model(&models.UserGroup{}).Where("group_id = ?", id).Count(&members).Error)
	return g.Name, !g.DeletedAt.Valid, members
}

type scimGroupOp struct {
	name string
	// do runs the operation against group gid; u2 is a second SCIM-managed user that
	// is not yet a member.
	do func(h *SCIMHandler, gid, u2 string) *httptest.ResponseRecorder
	// mutates: a failed run must leave the group exactly as provisioned.
	mutates bool
}

// The operations are chosen so each is ONE commit (no member removal combined with an
// add or rename: that is the split path, whose failures are a PartialMutation 503, a
// different contract tested in owed_audit_split_ops_test.go).
var scimGroupOps = []scimGroupOp{
	{"GET", func(h *SCIMHandler, gid, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.GetGroup, http.MethodGet, gid, "")
	}, false},
	{"PUT rename", func(h *SCIMHandler, gid, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.ReplaceGroup, http.MethodPut, gid, `{"displayName":"Renamed"}`)
	}, true},
	{"PATCH add member", func(h *SCIMHandler, gid, u2 string) *httptest.ResponseRecorder {
		return scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
			`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+u2+`"}]}]}`)
	}, true},
	{"PATCH rename", func(h *SCIMHandler, gid, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
			`{"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}`)
	}, true},
	{"DELETE", func(h *SCIMHandler, gid, _ string) *httptest.ResponseRecorder {
		return scimGroupDo(h.DeleteGroup, http.MethodDelete, gid, "")
	}, true},
}

// scimGroupFaultSites are the storage calls an operation makes (nth = which call of that
// method, counted from the moment the fault is armed, after setup). A fault at any of
// them must be a 500. A site is used only by the operations in `ops`.
var scimGroupFaultSites = []struct {
	method string
	nth    int
	ops    []string
}{
	{"GetGroup", 1, []string{"GET", "PUT rename", "PATCH add member", "PATCH rename", "DELETE"}},
	{"ListGroupMembers", 1, []string{"PUT rename"}},
	{"GetUser", 1, []string{"PATCH add member"}}, // the SCIM-managed membership check
	{"UpdateGroupFields", 1, []string{"PUT rename", "PATCH rename"}},
	{"AddUserToGroup", 1, []string{"PATCH add member"}},
	{"DeleteGroup", 1, []string{"DELETE"}},
	{"WithTransaction", 1, []string{"PUT rename", "PATCH add member", "PATCH rename", "DELETE"}},
}

func (o scimGroupOp) uses(method string) bool {
	for _, s := range scimGroupFaultSites {
		if s.method != method {
			continue
		}
		for _, n := range s.ops {
			if n == o.name {
				return true
			}
		}
	}
	return false
}

// TestSCIM_GroupStorageError_Is500NotNotFound is the #3620 regression: every storage
// failure on GET/PUT/PATCH/DELETE answers 500 with the generic detail (never a 404 the
// IdP reads as "the group is gone", never a 4xx it does not retry), the injected text
// stays in the server log, and a failed write left the group as it was.
func TestSCIM_GroupStorageError_Is500NotNotFound(t *testing.T) {
	for _, op := range scimGroupOps {
		for _, site := range scimGroupFaultSites {
			if !op.uses(site.method) {
				continue
			}
			for kind, ferr := range scimStorageFaults {
				t.Run(op.name+"/"+site.method+"/"+kind, func(t *testing.T) {
					h, fs, db := setupSCIMFaultTest(t)
					u1 := provisionUser(t, h, "u1@corp.com")
					u2 := provisionUser(t, h, "u2@corp.com")
					gid := provisionGroup(t, h, "Engineers", u1)
					logBuf := captureLogBuf(t)

					fs.Arm(&faultstorage.FaultSpec{Method: site.method, NthCall: site.nth, Kind: faultstorage.KindError, Err: ferr})
					w := op.do(h, gid, u2)
					require.True(t, fs.Fired(), "the armed %s fault must have fired", site.method)
					fs.Arm(nil)

					body := assertSCIMErrorBody(t, w, http.StatusInternalServerError)
					assert.Equal(t, clientSafe(ferr), body["detail"])
					assert.Nil(t, body["scimType"])
					assert.Contains(t, logBuf.String(), scimInjectedDetail, "the real error must be logged for the operator")
					if op.mutates {
						name, live, members := scimGroupState(t, db, gid)
						assert.Equal(t, "Engineers", name, "a failed write must not rename the group")
						assert.True(t, live, "a failed write must not delete the group")
						assert.EqualValues(t, 1, members, "a failed write must not change the members")
					}
				})
			}
		}
	}
}

// TestSCIM_CreateGroupStorageError_Is500: a storage failure on create is not the IdP's
// fault; it used to be a 400, which an IdP does not retry. A duplicate name is 409
// "uniqueness".
func TestSCIM_CreateGroupStorageError_Is500(t *testing.T) {
	create := func(h *SCIMHandler, name string, members ...string) *httptest.ResponseRecorder {
		ms := ""
		for i, m := range members {
			if i > 0 {
				ms += ","
			}
			ms += `{"value":"` + m + `"}`
		}
		return scimGroupDo(h.CreateGroup, http.MethodPost, "", `{"displayName":"`+name+`","members":[`+ms+`]}`)
	}
	for _, site := range []string{"CreateGroup", "AddUserToGroup", "GetUser", "WithTransaction"} {
		for kind, ferr := range scimStorageFaults {
			t.Run(site+"/"+kind, func(t *testing.T) {
				h, fs, db := setupSCIMFaultTest(t)
				u1 := provisionUser(t, h, "u1@corp.com")
				logBuf := captureLogBuf(t)

				fs.Arm(&faultstorage.FaultSpec{Method: site, NthCall: 1, Kind: faultstorage.KindError, Err: ferr})
				w := create(h, "Engineers", u1)
				require.True(t, fs.Fired(), "the armed %s fault must have fired", site)
				fs.Arm(nil)

				body := assertSCIMErrorBody(t, w, http.StatusInternalServerError)
				assert.Equal(t, clientSafe(ferr), body["detail"])
				assert.Contains(t, logBuf.String(), scimInjectedDetail)
				var n int64
				require.NoError(t, db.Model(&models.Group{}).Count(&n).Error)
				assert.Zero(t, n, "a failed create must leave no group behind")
			})
		}
	}
	t.Run("duplicate name", func(t *testing.T) {
		h, _, _ := setupSCIMFaultTest(t)
		require.Equal(t, http.StatusCreated, create(h, "Dup").Code)
		body := assertSCIMErrorBody(t, create(h, "Dup"), http.StatusConflict)
		assert.Equal(t, "uniqueness", body["scimType"])
	})
	t.Run("duplicate name via unique index", func(t *testing.T) {
		h, fs, _ := setupSCIMFaultTest(t)
		fs.Arm(&faultstorage.FaultSpec{Method: "CreateGroup", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("%s: %w", scimInjectedDetail, corestorage.ErrDuplicateGroupName)})
		w := create(h, "Race")
		require.True(t, fs.Fired())
		body := assertSCIMErrorBody(t, w, http.StatusConflict)
		assert.Equal(t, "uniqueness", body["scimType"])
	})
}

// TestSCIM_GroupRenameToExistingName_Is409: PUT/PATCH renaming a group onto another
// group's name hits the unique index; that is the IdP's conflict (409), not "the group
// does not exist" (404).
func TestSCIM_GroupRenameToExistingName_Is409(t *testing.T) {
	for _, op := range []string{"PUT", "PATCH"} {
		t.Run(op, func(t *testing.T) {
			h, _, _ := setupSCIMFaultTest(t)
			provisionGroup(t, h, "Taken")
			gid := provisionGroup(t, h, "Mine")
			var w *httptest.ResponseRecorder
			if op == "PUT" {
				w = scimGroupDo(h.ReplaceGroup, http.MethodPut, gid, `{"displayName":"Taken"}`)
			} else {
				w = scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
					`{"Operations":[{"op":"replace","path":"displayName","value":"Taken"}]}`)
			}
			body := assertSCIMErrorBody(t, w, http.StatusConflict)
			assert.Equal(t, "uniqueness", body["scimType"])
		})
	}
}

// TestSCIM_GroupMemberNotSCIMManaged_Is400: a member id the group sync may not add (a
// native account, or no such user) is the request's fault, a 400 "invalidValue" for
// all three writes (PUT/PATCH used to answer 404, which reads as "the group is gone").
// A storage failure while checking the member is NOT that refusal: it is a 500.
func TestSCIM_GroupMemberNotSCIMManaged_Is400(t *testing.T) {
	setup := func(t *testing.T) (*SCIMHandler, *faultstorage.FaultyStorage, string, string) {
		h, fs, db := setupSCIMFaultTest(t)
		native := &models.User{Username: "native", Email: "native@corp.com", IsActive: true, AccountState: "active"}
		require.NoError(t, db.Create(native).Error)
		return h, fs, provisionGroup(t, h, "Engineers"), strconv.FormatUint(uint64(native.ID), 10)
	}
	ops := map[string]func(h *SCIMHandler, gid, member string) *httptest.ResponseRecorder{
		"POST": func(h *SCIMHandler, _, member string) *httptest.ResponseRecorder {
			return scimGroupDo(h.CreateGroup, http.MethodPost, "", `{"displayName":"New","members":[{"value":"`+member+`"}]}`)
		},
		"PUT": func(h *SCIMHandler, gid, member string) *httptest.ResponseRecorder {
			return scimGroupDo(h.ReplaceGroup, http.MethodPut, gid, `{"displayName":"Engineers","members":[{"value":"`+member+`"}]}`)
		},
		"PATCH": func(h *SCIMHandler, gid, member string) *httptest.ResponseRecorder {
			return scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
				`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+member+`"}]}]}`)
		},
	}
	for name, do := range ops {
		t.Run(name+"/native account", func(t *testing.T) {
			h, _, gid, native := setup(t)
			body := assertSCIMErrorBody(t, do(h, gid, native), http.StatusBadRequest)
			assert.Equal(t, "invalidValue", body["scimType"])
		})
		t.Run(name+"/no such user", func(t *testing.T) {
			h, _, gid, _ := setup(t)
			body := assertSCIMErrorBody(t, do(h, gid, "999999"), http.StatusBadRequest)
			assert.Equal(t, "invalidValue", body["scimType"])
		})
		t.Run(name+"/member lookup fails", func(t *testing.T) {
			h, fs, gid, _ := setup(t)
			u := provisionUser(t, h, "scim@corp.com")
			fs.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
			w := do(h, gid, u)
			require.True(t, fs.Fired())
			fs.Arm(nil)
			assertSCIMErrorBody(t, w, http.StatusInternalServerError)
		})
	}
}

// TestSCIM_GroupConfersAdmin_Is403: adding members to a group that grants an admin
// role is a deliberate, permanent refusal (403), not a missing group (404) and not
// something to retry. A storage failure while reading the group's roles is a 500.
func TestSCIM_GroupConfersAdmin_Is403(t *testing.T) {
	setup := func(t *testing.T) (*SCIMHandler, *faultstorage.FaultyStorage, string, string) {
		h, fs, db := setupSCIMFaultTest(t)
		u := provisionUser(t, h, "u@corp.com")
		gid := provisionGroup(t, h, "Admins")
		admin := &models.Role{Name: "admin", BypassesPermissionChecks: true}
		require.NoError(t, db.Create(admin).Error)
		g, err := strconv.ParseUint(gid, 10, 32)
		require.NoError(t, err)
		require.NoError(t, db.Create(&models.GroupRole{GroupID: uint(g), RoleID: admin.ID}).Error)
		return h, fs, gid, u
	}
	ops := map[string]func(h *SCIMHandler, gid, member string) *httptest.ResponseRecorder{
		"PUT": func(h *SCIMHandler, gid, member string) *httptest.ResponseRecorder {
			return scimGroupDo(h.ReplaceGroup, http.MethodPut, gid, `{"displayName":"Admins","members":[{"value":"`+member+`"}]}`)
		},
		"PATCH": func(h *SCIMHandler, gid, member string) *httptest.ResponseRecorder {
			return scimGroupDo(h.PatchGroup, http.MethodPatch, gid,
				`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+member+`"}]}]}`)
		},
	}
	for name, do := range ops {
		t.Run(name+"/refused", func(t *testing.T) {
			h, _, gid, u := setup(t)
			assertSCIMErrorBody(t, do(h, gid, u), http.StatusForbidden)
		})
		t.Run(name+"/role lookup fails", func(t *testing.T) {
			h, fs, gid, u := setup(t)
			fs.Arm(&faultstorage.FaultSpec{Method: "GetGroupRoles", NthCall: 1, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
			w := do(h, gid, u)
			require.True(t, fs.Fired())
			fs.Arm(nil)
			assertSCIMErrorBody(t, w, http.StatusInternalServerError)
		})
	}
}

// TestSCIM_DeleteLastAdminGroup_Is409: deleting the group that holds the install's last
// administrative grant is a permanent refusal (409, like the last-admin user
// deactivation), not a 404.
func TestSCIM_DeleteLastAdminGroup_Is409(t *testing.T) {
	h, _, db := setupSCIMFaultTest(t)
	gid := provisionGroup(t, h, "Admins")
	admin := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(admin).Error)
	g, err := strconv.ParseUint(gid, 10, 32)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: uint(g), RoleID: admin.ID}).Error)
	// A member who holds the admin tier only through this group.
	u := provisionUser(t, h, "u@corp.com")
	uid, err := strconv.ParseUint(u, 10, 32)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserGroup{UserID: uint(uid), GroupID: uint(g)}).Error)

	w := scimGroupDo(h.DeleteGroup, http.MethodDelete, gid, "")
	assertSCIMErrorBody(t, w, http.StatusConflict)
	_, live, _ := scimGroupState(t, db, gid)
	assert.True(t, live)
}
