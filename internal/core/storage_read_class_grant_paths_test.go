package core

// storage_read_class_grant_paths_test.go — STORAGE-ERR-CLASS-2 item 2.
//
// Grant / create / renew paths read a parent (project, environment, role, secret)
// and refuse with a not-found or validation verdict. They already fail closed, but a
// read FAULT was reported as "unknown role" / "project not found" / "secret no longer
// exists", so a database outage looked like the caller's own mistake and was not
// retried. A fault is now ErrStorageReadUnavailable; an absent parent keeps its text.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sweepReadFault arms an error on the 1st, 2nd, ... call of method, runs call once
// per arming and stops when the call no longer reaches that many calls. Every fault
// must come back either as ErrStorageReadUnavailable or at least without the folded
// verdict text; the number that were classified is returned so the caller can require
// the site under test was reached. (FaultSpec matches by call count, not arguments,
// so the sweep finds the site without hard-coding which call it is.)
func sweepReadFault(t *testing.T, faulty *faultstorage.FaultyStorage, method, folded string, call func() error) (classified int) {
	t.Helper()
	defer faulty.Arm(nil)
	for nth := 1; nth <= 12; nth++ {
		faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindError, Err: assert.AnError})
		err := call()
		if !faulty.Fired() {
			return classified
		}
		if err == nil {
			continue
		}
		if IsStorageReadUnavailable(err) {
			classified++
			assert.NotContains(t, err.Error(), "not found")
			assert.ErrorIs(t, err, assert.AnError, "the cause stays reachable for the server log")
			continue
		}
		assert.NotContains(t, err.Error(), folded, "%s fault #%d was folded into the not-found verdict", method, nth)
	}
	return classified
}

func TestStorageReadClass_GrantPaths(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			admin := w.user()
			require.NoError(t, w.core.storage.AssignRole(ctx, admin.ID, w.role(true).ID, Scope{}))
			p := w.project()
			role := w.role(true)
			uname := func() string { return w.name("grantpath") }

			t.Run("CreateUserWithAssignments: system role lookup", func(t *testing.T) {
				call := func() error {
					n := uname()
					_, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{Username: n, Email: n + "@example.com", DisplayName: n, Password: "Correct-Horse-Battery-9"},
						role.Name, nil, admin.ID, false)
					return err
				}
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetRoleByName", "unknown role", call), 1)
				n := uname()
				_, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{Username: n, Email: n + "@example.com", DisplayName: n, Password: "Correct-Horse-Battery-9"},
					"no-such-role-"+n, nil, admin.ID, false)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "unknown role")
			})

			t.Run("resolveProjectRoleGrant: project and role lookups", func(t *testing.T) {
				call := func() error {
					_, err := c.resolveProjectRoleGrant(ctx, admin.ID, false, ProjectAssignment{ProjectID: p.ID, Role: role.Name})
					return err
				}
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetProject", "unknown project", call), 1)
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetRoleByName", "unknown role", call), 1)

				_, err := c.resolveProjectRoleGrant(ctx, admin.ID, false, ProjectAssignment{ProjectID: 9_999_999, Role: role.Name})
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "unknown project")
				_, err = c.resolveProjectRoleGrant(ctx, admin.ID, false, ProjectAssignment{ProjectID: p.ID, Role: "no-such-role"})
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "unknown role")
			})

			t.Run("ValidateRoleGrantAuthority: role lookup", func(t *testing.T) {
				grants := []storage.RoleGrant{{RoleID: role.ID, Scope: storage.Scope{ProjectID: p.ID}}}
				call := func() error { return c.ValidateRoleGrantAuthority(ctx, admin.ID, false, grants) }
				require.NoError(t, call(), "baseline: the admin may grant")
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetRole", "unknown role id", call), 1)
				err := c.ValidateRoleGrantAuthority(ctx, admin.ID, false, []storage.RoleGrant{{RoleID: 9_999_999}})
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "unknown role id")
			})

			t.Run("CreateEnvironment: parent project lookup", func(t *testing.T) {
				call := func() error {
					_, err := c.CreateEnvironment(ctx, p.ID, uname())
					return err
				}
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetProject", "project not found", call), 1)
				_, err := c.CreateEnvironment(ctx, 9_999_999, uname())
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "project not found")
				_, err = c.CreateEnvironment(ctx, p.ID, uname())
				require.NoError(t, err, "the retried create succeeds")
			})

			t.Run("CopyEnvironmentSecrets: environment lookup", func(t *testing.T) {
				env := w.env(p.ID)
				other := w.project()
				call := func() error {
					_, err := c.projectEnvironment(ctx, p.ID, env.ID)
					return err
				}
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetEnvironment", "must belong", call), 1)
				// Absent and cross-project are one answer, and not a fault.
				_, errGone := c.projectEnvironment(ctx, p.ID, 9_999_999)
				_, errCross := c.projectEnvironment(ctx, other.ID, env.ID)
				require.Error(t, errGone)
				require.Error(t, errCross)
				assert.Equal(t, errGone.Error(), errCross.Error())
				assert.False(t, IsStorageReadUnavailable(errGone))
			})
		})
	}
}

func TestStorageReadClass_ApproveSecretAccessRequest(t *testing.T) {
	t.Parallel()
	base, st := newBootstrappedCore(t)
	secretID, _, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	faulty := faultstorage.NewFaultyStorage(st, nil)
	c := NewKeyorixCore(faulty)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)

	// A fresh pending request per call: a fault that lands after the approval write
	// (a swallowed best-effort read) leaves that request approved, which must not
	// leak into the next arming.
	n := 0
	fresh := func() *models.AccessRequest {
		n++
		u, err := st.CreateUser(ctx, foldedTestUser(t, fmt.Sprintf("grant-req-%d", n), fmt.Sprintf("grant-req-%d@example.com", n)))
		require.NoError(t, err)
		require.NoError(t, st.AssignRole(ctx, u.ID, viewer.ID, storage.Scope{ProjectID: projectID}))
		req, err := base.RequestSecretAccess(ctx, secretID, u.ID, "")
		require.NoError(t, err)
		return req
	}
	approve := func() error {
		req := fresh()
		_, err := c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
		if IsStorageReadUnavailable(err) {
			got, gerr := st.GetAccessRequest(ctx, req.ID)
			require.NoError(t, gerr)
			assert.Equal(t, AccessRequestPending, got.State, "a refused approve left the request pending")
		}
		return err
	}

	// The access request is read before and the secret after; faulting either must
	// answer "retry", never "access request not found" / "secret no longer exists".
	assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetSecret", "no longer exists", approve), 1)
	assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetAccessRequest", "access request not found", approve), 1)

	_, err = c.ApproveSecretAccessRequest(ctx, 999999, approverID)
	assert.EqualError(t, err, "access request not found", "a true not-found keeps its text")
	require.NoError(t, approve(), "the retried approve succeeds")
}
