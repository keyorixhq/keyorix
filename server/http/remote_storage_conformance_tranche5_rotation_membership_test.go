// remote_storage_conformance_tranche5_rotation_membership_test.go — issue
// #1808, tranche 5.
//
// Covers 3 methods left uncovered by tranche 4:
//
//	CreateRotationPolicy, UpdateRotationPolicy (internal/storage/store/
//	remote_rotation_policies.go): tranche 4's own dynamic_rotation file
//	SKIPPED both, documenting a confirmed, currently-shipping wire bug --
//	models.RotationPolicy carries no json tags, so posting it directly
//	marshaled every multi-word field (IntervalDays, ProjectID, EnvironmentID,
//	AlertDaysBefore, NotifyOnBreach, IsActive, CreatedBy) as PascalCase, which
//	never case-insensitively matches the server's snake_case-tagged reqBody,
//	silently zeroing all of them and tripping the server's own
//	`interval_days must be at least 1` validation on every single call. THAT
//	BUG IS NOW FIXED (PR #1832): remote_rotation_policies.go now builds
//	explicit rotationPolicyCreateWire/rotationPolicyUpdateWire request types
//	with correct snake_case json tags. Real, passing conformance tests for
//	both methods are written below, with assertions strong enough to have
//	caught the original bug (asserting exact non-default, non-zero values for
//	every previously-zeroed multi-word field, not just "no error").
//
//	TransitionProjectMembershipState (internal/storage/store/
//	remote_memberships.go): tranche 4's own memberships_auth file SKIPPED
//	this one too, for a different reason -- its proxy route
//	(TransitionMembershipProxy) is not a raw CAS passthrough. It delegates to
//	core.TransitionMembership, which re-derives fromState from a fresh read
//	(ignoring the wire's own from_state), enforces canTransition legality
//	server-side, and on a transition INTO "active" applies a role-grant side
//	effect gated by its own permission ceiling. That file's header named this
//	as needing "two FULL core.TransitionMembership executions... left for a
//	dedicated future tranche" -- this is that tranche. Using the same
//	technique TestConformance_DeleteUser (tranche 4) established for an
//	asymmetric core-delegating route: compare h.upstreamCore.TransitionMembership
//	called in-process against h.rs.TransitionProjectMembershipState called
//	over the real router, on independently-seeded memberships in the same
//	states.
//
//	A real, CONFIRMED asymmetry was found while writing this test (not
//	glossed over -- see TestConformance_TransitionProjectMembershipState's own
//	doc comment below for the full trace): activating a membership
//	(provisioned -> active, the ONE transition with a role-grant side effect)
//	via RemoteStorage's proxy route is refused UNCONDITIONALLY for this
//	harness's node/machine credential, for any role that carries at least one
//	permission -- TransitionMembershipProxy never tags its context with
//	core.WithSelfMachineGranter the way the human-facing
//	project_memberships.go route does, so requireGranterHoldsRolePermissions
//	treats the untagged machine actor as holding zero permissions and refuses
//	unconditionally, regardless of the credential's real admin role. This is
//	a genuine, pre-existing route-design gap (out of this tranche's scope to
//	fix -- only one new file may be added), not a fixture-cost skip: the
//	method IS exercised below, including this confirmed divergence, rather
//	than faked with a shallow comparison or silently worked around. Every
//	OTHER transition (which does not touch this permission ceiling) is
//	asserted for genuine, full parity between the two paths.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- CreateRotationPolicy ---

func TestConformance_CreateRotationPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Local sanity baseline: LocalStorage.CreateRotationPolicy is a bare GORM
	// Create with zero business logic (local_rotation_policies.go) -- every
	// field is set explicitly, including RotationState ("idle"), matching
	// what GORM's own `gorm:"default:'idle'"` would otherwise silently
	// substitute for a zero-valued field on Create, so this comparison isn't
	// fighting the DB's own defaulting behavior.
	localSent := &models.RotationPolicy{
		Name: "conformance-crp-local", Description: "local desc", Scope: "project",
		ProjectID: uintPtr(h.projectID), IntervalDays: 45, AlertDaysBefore: 3,
		NotifyOnBreach: true, IsActive: true, RotationState: "idle", CreatedBy: "conformance-test",
	}
	require.NoError(t, h.ls.CreateRotationPolicy(ctx, localSent))
	localPersisted, err := h.ls.GetRotationPolicy(ctx, localSent.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateRotationPolicy (sanity baseline)", localSent, localPersisted, map[string]bool{
		"UpdatedAt": true, // GORM auto-set on Create
	})

	// Remote: CreateRotationPolicyProxy (rotation_policies_handler.go's
	// Create) routes through the FULL core.CreateRotationPolicy business
	// logic, not a raw passthrough -- it force-sets IsActive:true and derives
	// CreatedBy from the authenticated caller server-side. Neither field is
	// even carried by rotationPolicyCreateWire, so a caller cannot influence
	// either over the wire at all -- IsActive/CreatedBy are deliberately set
	// to forged/wrong values below to prove that.
	//
	// IntervalDays/AlertDaysBefore/ProjectID are deliberately given distinct,
	// non-zero, non-default values (45, 3) -- this is the exact defect class
	// tranche 4's own SKIPPED writeup found: every one of these previously
	// decoded to its Go zero value server-side (models.RotationPolicy has no
	// json tags, and encoding/json's case-insensitive fallback match cannot
	// bridge "IntervalDays" to "interval_days" -- the strings differ by more
	// than case), which tripped the server's own `interval_days` validation
	// and made both methods fail unconditionally. NotifyOnBreach is
	// deliberately NOT used to prove this on the CREATE path: GORM's own
	// `gorm:"default:true"` on RotationPolicy.NotifyOnBreach means a
	// zero-valued (false) field is silently coerced to true by Create
	// regardless of whether it was ever set correctly, so a true round-trip
	// here alone would not distinguish "correctly sent" from "silently
	// dropped and defaulted the same way" -- NotifyOnBreach:false genuinely
	// surviving a Save (not a Create) is what TestConformance_UpdateRotationPolicy
	// below proves instead, where no such default-coercion exists.
	remoteSent := &models.RotationPolicy{
		Name: "conformance-crp-remote", Description: "remote desc", Scope: "project",
		ProjectID: uintPtr(h.projectID), IntervalDays: 45, AlertDaysBefore: 3,
		NotifyOnBreach: true,
		// Deliberately wrong: rotationPolicyCreateWire carries neither field at
		// all, so the server cannot even receive these -- both must be forced
		// server-side, never silently reflect these forged local values.
		IsActive:  false,
		CreatedBy: "conformance-crp-forged-creator",
	}
	require.NoError(t, h.rs.CreateRotationPolicy(ctx, remoteSent),
		"RemoteStorage.CreateRotationPolicy must succeed now that the wire fix (rotationPolicyCreateWire) "+
			"correctly encodes multi-word fields as snake_case -- this used to fail unconditionally with the "+
			"server's own 400 \"interval_days must be at least 1\"")

	// remoteSent has been mutated in place to the decoded response
	// (RemoteStorage.CreateRotationPolicy's own `*p = result` contract) -- the
	// key regression assertions, strong enough to have caught the original
	// bug (which zeroed every one of these before the fix).
	assert.Equal(t, 45, remoteSent.IntervalDays,
		"IntervalDays must round-trip over the wire -- the exact field whose zeroing tripped the server's "+
			"own interval_days validation and made this method fail unconditionally before the fix")
	assert.Equal(t, 3, remoteSent.AlertDaysBefore, "AlertDaysBefore must round-trip over the wire")
	require.NotNil(t, remoteSent.ProjectID, "ProjectID must round-trip over the wire, not be silently dropped")
	assert.Equal(t, h.projectID, *remoteSent.ProjectID)
	assert.True(t, remoteSent.NotifyOnBreach, "NotifyOnBreach must round-trip over the wire")
	assert.True(t, remoteSent.IsActive,
		"core.CreateRotationPolicy always forces IsActive:true server-side, regardless of the forged false "+
			"input above -- the create wire carries no is_active field at all")
	assert.NotEqual(t, "conformance-crp-forged-creator", remoteSent.CreatedBy,
		"CreatedBy must be derived from the authenticated caller server-side -- rotationPolicyCreateWire "+
			"carries no created_by field at all, so a caller cannot even transmit one")
	assert.NotEmpty(t, remoteSent.CreatedBy, "sanity: the server-derived CreatedBy must still be populated")

	remotePersisted, err := h.ls.GetRotationPolicy(ctx, remoteSent.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateRotationPolicy (response fidelity: wire-returned vs persisted)",
		remoteSent, remotePersisted, map[string]bool{
			"CreatedAt": true, // GORM/SQLite timezone round-trip quirk, defensive
			"UpdatedAt": true, // GORM auto-set on Create
		})
}

// --- UpdateRotationPolicy ---

func TestConformance_UpdateRotationPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newPolicy := func(name string) *models.RotationPolicy {
		p := &models.RotationPolicy{
			Name: name, Description: "original desc", Scope: "project", ProjectID: uintPtr(h.projectID),
			IntervalDays: 30, AlertDaysBefore: 7, NotifyOnBreach: true, IsActive: true,
			RotationState: "idle", CreatedBy: "conformance-test",
		}
		require.NoError(t, h.ls.CreateRotationPolicy(ctx, p))
		return p
	}

	// Local sanity baseline: LocalStorage.UpdateRotationPolicy is a bare GORM
	// Save (full-row overwrite) with zero business logic -- mutate the
	// already-persisted struct directly (it already carries the real
	// ID/Scope/ProjectID/CreatedBy/RotationState from CreateRotationPolicy
	// above) and Save it, mirroring what core.UpdateRotationPolicy's own
	// fetch-then-patch achieves for the remote path below.
	localPolicy := newPolicy("conformance-urp-local")
	localPolicy.Name = "conformance-urp-local-changed"
	localPolicy.Description = "changed desc"
	localPolicy.IntervalDays = 60
	localPolicy.AlertDaysBefore = 10
	localPolicy.NotifyOnBreach = false
	localPolicy.IsActive = false
	require.NoError(t, h.ls.UpdateRotationPolicy(ctx, localPolicy))
	localPersisted, err := h.ls.GetRotationPolicy(ctx, localPolicy.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.UpdateRotationPolicy (sanity baseline)", localPolicy, localPersisted, map[string]bool{
		"UpdatedAt": true, // GORM auto-set on Save
	})

	// Remote: UpdateRotationPolicyProxy routes through the FULL
	// core.UpdateRotationPolicy business logic, which fetches the existing
	// row FIRST and patches only Name/Description/IntervalDays/
	// AlertDaysBefore/NotifyOnBreach/IsActive onto it -- confirmed against
	// rotation_policies_handler.go's Update reqBody and
	// core.UpdateRotationPolicyRequest directly, not assumed: neither has a
	// scope-family field. Every one of Scope/ProjectID/EnvironmentID/
	// CreatedBy/RotationState must therefore survive the update UNCHANGED
	// from whatever CreateRotationPolicy originally persisted -- proven below
	// by comparing against a pre-update snapshot, not merely assumed to hold.
	remotePolicy := newPolicy("conformance-urp-remote")
	preUpdateProjectID := *remotePolicy.ProjectID
	preUpdateScope := remotePolicy.Scope
	preUpdateCreatedBy := remotePolicy.CreatedBy
	preUpdateRotationState := remotePolicy.RotationState

	remoteSent := &models.RotationPolicy{
		ID: remotePolicy.ID, Name: "conformance-urp-remote-changed", Description: "changed desc",
		IntervalDays: 60, AlertDaysBefore: 10, NotifyOnBreach: false, IsActive: false,
	}
	require.NoError(t, h.rs.UpdateRotationPolicy(ctx, remoteSent),
		"RemoteStorage.UpdateRotationPolicy must succeed now that the wire fix (rotationPolicyUpdateWire) "+
			"correctly encodes multi-word fields as snake_case")

	// remoteSent is mutated in place to the decoded response -- the key
	// regression assertions (every one of these fields previously decoded to
	// its zero value server-side before the fix).
	assert.Equal(t, 60, remoteSent.IntervalDays, "IntervalDays must round-trip over the wire")
	assert.Equal(t, 10, remoteSent.AlertDaysBefore, "AlertDaysBefore must round-trip over the wire")
	assert.False(t, remoteSent.NotifyOnBreach,
		"NotifyOnBreach:false must survive a Save -- unlike Create, GORM applies no column-default "+
			"substitution on Save's update path, so this genuinely proves the field crossed the wire as "+
			"false rather than merely defaulting true and coincidentally matching (see the CREATE test's "+
			"comment on this exact ambiguity)")
	assert.False(t, remoteSent.IsActive,
		"IsActive:false must round-trip over the wire -- update is the one place this tranche's brief calls "+
			"out IsActive specifically, and it is a multi-word field (\"is_active\") that was silently zeroed "+
			"pre-fix along with every other field in this same request")
	assert.Equal(t, "conformance-urp-remote-changed", remoteSent.Name)
	assert.Equal(t, "changed desc", remoteSent.Description)

	// Fields the update wire does NOT carry must survive untouched from
	// whatever CreateRotationPolicy originally persisted.
	require.NotNil(t, remoteSent.ProjectID)
	assert.Equal(t, preUpdateProjectID, *remoteSent.ProjectID, "ProjectID is not on the update wire -- must survive unchanged")
	assert.Equal(t, preUpdateScope, remoteSent.Scope, "Scope is not on the update wire -- must survive unchanged")
	assert.Equal(t, preUpdateCreatedBy, remoteSent.CreatedBy, "CreatedBy is not on the update wire -- must survive unchanged")
	assert.Equal(t, preUpdateRotationState, remoteSent.RotationState, "RotationState is not on the update wire -- must survive unchanged")

	remotePersisted, err := h.ls.GetRotationPolicy(ctx, remoteSent.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "RemoteStorage.UpdateRotationPolicy (response fidelity: wire-returned vs persisted)",
		remoteSent, remotePersisted, map[string]bool{
			"CreatedAt": true, // GORM/SQLite timezone round-trip quirk, defensive
			"UpdatedAt": true, // GORM auto-set on Save
		})
}

// --- TransitionProjectMembershipState ---
//
// See this file's package doc for the full context. Summary of what's proven
// below:
//
//   - (a) invited -> identity_verified: a legal transition that touches
//     neither canTransition's illegal-transition path nor the activation
//     permission ceiling (which only fires for to == active) -- a genuinely
//     fair, fully-comparable case. Both a real human actor (in-process) and
//     this harness's real node/machine credential (over HTTP) must produce
//     the identical resulting state.
//   - (b) invited -> active (illegal, skips identity_verified/provisioned):
//     canTransition is checked BEFORE the activation permission ceiling, so
//     this refusal is actor-independent and is ALSO a fair comparison. Exact
//     error text differs across the wire (clientSafe redacts everything to a
//     generic sentence except a literal "not found" substring elsewhere --
//     confirmed by tracing TransitionMembershipProxy/clientSafe directly),
//     so parity is asserted on the OUTCOME (row left unchanged on both
//     paths, both genuinely refuse), not on byte-identical error strings.
//   - (c) provisioned -> active: the one transition with a role-grant side
//     effect (AddProjectMember) AND a permission ceiling
//     (requireGranterHoldsRolePermissions). A real human actor succeeds and
//     the role grant lands. This harness's node/machine credential going
//     through TransitionMembershipProxy is refused UNCONDITIONALLY for any
//     role carrying at least one permission (system_viewer does):
//     TransitionMembershipProxy never tags its context with
//     core.WithSelfMachineGranter the way the human-facing
//     project_memberships.go route does, so requireGranterHoldsRolePermissions
//     treats the untagged machine actor as holding zero permissions and
//     refuses every permission check unconditionally -- regardless of the
//     credential's real admin role. This is a genuine, pre-existing route
//     design gap (confirmed by direct code trace of
//     internal/core/authz.go's requireGranterHoldsRolePermissions and
//     server/http/handlers/project_memberships_proxy.go's
//     TransitionMembershipProxy, not theorized), not a wire-fidelity defect
//     this tranche's own scope covers fixing (only one new file may be
//     added) -- asserted explicitly below, including that the refused
//     attempt left both the row and the role grant untouched (fails closed,
//     no partial side effect), rather than silently worked around.
func TestConformance_TransitionProjectMembershipState(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newMembership := func(suffix, state string) (*models.User, *models.ProjectMembership) {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-tpms-" + suffix, Email: "conformance-tpms-" + suffix + "@example.com",
			DisplayName: "Conformance TransitionProjectMembershipState " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		m, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
			ProjectID: h.projectID, UserID: user.ID, Role: "system_viewer", State: state,
			InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
		return user, m
	}

	// (a) Legal transition, no permission ceiling, no side effect.
	_, localMembershipA := newMembership("a-local", core.MembershipInvited)
	updatedLocalA, err := h.upstreamCore.TransitionMembership(ctx, h.projectID, localMembershipA.ID, core.MembershipIdentityVerified, h.adminUserID, false)
	require.NoError(t, err, "sanity: invited -> identity_verified must be legal for a real human actor")
	assert.Equal(t, core.MembershipIdentityVerified, updatedLocalA.State)

	_, remoteMembershipA := newMembership("a-remote", core.MembershipInvited)
	remoteMatchedA, err := h.rs.TransitionProjectMembershipState(ctx, &models.ProjectMembership{
		ID: remoteMembershipA.ID, ProjectID: h.projectID, State: core.MembershipIdentityVerified,
	}, core.MembershipInvited)
	require.NoError(t, err, "RemoteStorage.TransitionProjectMembershipState must succeed for a legal transition "+
		"that doesn't touch the activation permission ceiling")
	assert.True(t, remoteMatchedA)
	remoteAfterA, err := h.ls.GetProjectMembership(ctx, remoteMembershipA.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipIdentityVerified, remoteAfterA.State,
		"the remote transition must have actually persisted server-side, matching the in-process result exactly")

	// (b) Illegal transition, refused identically on both paths.
	_, illegalLocalMembership := newMembership("b-local", core.MembershipInvited)
	_, err = h.upstreamCore.TransitionMembership(ctx, h.projectID, illegalLocalMembership.ID, core.MembershipActive, h.adminUserID, false)
	require.Error(t, err, "sanity: invited -> active must be refused as an illegal transition")
	assert.Contains(t, err.Error(), "cannot transition membership from",
		"sanity: must be refused for the RIGHT reason (illegal transition, not some other failure)")
	stillInvitedLocal, err := h.ls.GetProjectMembership(ctx, illegalLocalMembership.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipInvited, stillInvitedLocal.State, "a refused illegal transition must not have altered the row")

	_, illegalRemoteMembership := newMembership("b-remote", core.MembershipInvited)
	_, err = h.rs.TransitionProjectMembershipState(ctx, &models.ProjectMembership{
		ID: illegalRemoteMembership.ID, ProjectID: h.projectID, State: core.MembershipActive,
	}, core.MembershipInvited)
	require.Error(t, err, "RemoteStorage.TransitionProjectMembershipState must ALSO refuse invited -> active as "+
		"an illegal transition -- the SAME core.TransitionMembership canTransition check this route delegates to")
	assert.Contains(t, err.Error(), "STORAGE_ERROR",
		"the illegal-transition rejection surfaces as the generic internal-error code over HTTP (clientSafe "+
			"redacts the real message to a fixed generic sentence -- confirmed by tracing clientSafe directly, "+
			"not assumed) -- the row check below is what actually proves this was the SAME rejection, not some "+
			"unrelated failure that happened to also error")
	stillInvitedRemote, err := h.ls.GetProjectMembership(ctx, illegalRemoteMembership.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipInvited, stillInvitedRemote.State,
		"a refused illegal transition must not have altered the row server-side either")

	// (c) provisioned -> active: role-grant side effect + permission ceiling.
	// See this function's own doc comment above for the confirmed asymmetry.
	localUser, localProvisioned := newMembership("c-local", core.MembershipProvisioned)
	updatedLocalActive, err := h.upstreamCore.TransitionMembership(ctx, h.projectID, localProvisioned.ID, core.MembershipActive, h.adminUserID, false)
	require.NoError(t, err, "a real human actor activating a provisioned membership must succeed")
	assert.Equal(t, core.MembershipActive, updatedLocalActive.State)
	assert.NotNil(t, updatedLocalActive.ActivatedAt)
	localRoleIDs, err := h.ls.GetUserRoleIDsAt(ctx, localUser.ID, coreStorage.Scope{ProjectID: h.projectID})
	require.NoError(t, err)
	assert.NotEmpty(t, localRoleIDs,
		"activating a membership must apply its role-grant side effect (AddProjectMember) for a real human actor")

	remoteUser, remoteProvisioned := newMembership("c-remote", core.MembershipProvisioned)
	_, err = h.rs.TransitionProjectMembershipState(ctx, &models.ProjectMembership{
		ID: remoteProvisioned.ID, ProjectID: h.projectID, State: core.MembershipActive,
	}, core.MembershipProvisioned)
	assert.Error(t, err, "CONFIRMED ASYMMETRY (see this function's doc comment): activating a membership via "+
		"RemoteStorage's proxy route is refused unconditionally for this harness's machine credential, unlike "+
		"the identical in-process call above with a real human actor -- TransitionMembershipProxy never tags "+
		"ctx with core.WithSelfMachineGranter the way the human-facing route does")
	stillProvisionedRemote, err := h.ls.GetProjectMembership(ctx, remoteProvisioned.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipProvisioned, stillProvisionedRemote.State,
		"the refused activation must not have altered the row -- fails closed, not a partial/silent activation")
	remoteRoleIDs, err := h.ls.GetUserRoleIDsAt(ctx, remoteUser.ID, coreStorage.Scope{ProjectID: h.projectID})
	require.NoError(t, err)
	assert.Empty(t, remoteRoleIDs,
		"the refused activation must not have granted the role either -- no partial side effect from the failed attempt")
}
