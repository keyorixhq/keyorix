// remote_storage_conformance_tranche4_machine_identities_test.go — issue #1808,
// tranche 4.
//
// Selection: this tranche was assigned directly (not mechanically derived from
// TestReportConformancePopulation like tranches 2/3) — all 21 remaining methods
// declared on *RemoteStorage in internal/storage/store/remote_machine_identities.go
// that had no TestConformance_ test yet:
//
//	CountMachineIdentitiesByClassification, CountMachineIdentityCredentialsByClassification,
//	CreateMachineIdentity, CreateOIDCBinding, DeleteOIDCBinding, GetMachineByOIDCSubject,
//	GetMachineIdentity, GetMachineIdentityCredentialByHash, GetMachineIdentityCredentialByID,
//	GetMachineRoleIDsAt, GetMachineRoles, GetOIDCBindingByID, ListActiveMachineIdentityCredentials,
//	ListAllMachineIdentities, ListMachineIdentities, ListMachineIdentityCredentials,
//	ListOIDCBindings, LockMachineIdentityForUpdate, RemoveMachineRole,
//	TouchMachineIdentityCredential, UpdateMachineIdentityCredential
//
// (CreateMachineIdentityCredential and AssignMachineRole are used throughout as
// raw fixture-seeding helpers — mirroring tranche 2/3's own convention — but are
// NOT in this tranche's assigned list: AssignMachineRole already has a
// TestConformance_ test (tranche 3), and CreateMachineIdentityCredential was not
// assigned to this tranche.)
//
// Two genuine, confirmed asymmetries surfaced while reading
// server/http/handlers/machine_identities_proxy.go before writing these tests —
// both handled the way tranche 3's TransitionSecretStatus/RemoveGlobalAdminRoleGuarded
// handled their own narrowings: proven and documented, not silently assumed away.
//
//  1. CreateMachineIdentity's proxy (CreateMachineIdentityProxy) is NOT a raw
//     passthrough, unlike every other method in this file — it routes through
//     core.CreateMachineIdentity, which unconditionally forces State=MachineActive
//     and derives CreatedBy/CreatedByMachineIdentityID from the AUTHENTICATED actor
//     behind the request (never from the caller-supplied model), per that handler's
//     own G80 doc comment. TestConformance_CreateMachineIdentity proves this
//     explicitly with a deliberately-wrong State/CreatedBy/CreatedByMachineIdentityID
//     on the wire model and asserts the actor-derived values win.
//
//  2. UpdateMachineIdentityCredential's proxy (UpdateMachineIdentityCredentialProxy)
//     is likewise not a raw full-row Save — it routes through
//     core.ClassifyMachineTokenByID, which re-fetches the row SERVER-SIDE and
//     applies ONLY Classification, discarding TokenHash/Revoked/ExpiresAt/etc from
//     the wire body entirely (that handler's own #1542-shape-fix doc comment).
//     TestConformance_UpdateMachineIdentityCredential proves the narrowing directly:
//     it sends a forged TokenHash and Revoked=true alongside a genuine
//     Classification change and asserts only Classification lands.
//
// Also confirmed, THIS time by a failing assertion while writing this tranche
// (not just by reading code): the CreatedByMachineIdentityID field (#1573,
// present on models.MachineIdentity) is absent from BOTH
// remote_machine_identities.go's machineIdentityWire (client) and
// machine_identities_proxy.go's machineIdentityProxyWire (server) — dropped on
// every machine-identity response over RemoteStorage, including the CREATE
// response itself, not just later GET/List reads. TestConformance_CreateMachineIdentity
// originally asserted the CREATE response's own CreatedByMachineIdentityID was
// non-zero (since the actor behind h.rs's request IS a real machine identity,
// so core.CreateMachineIdentity's server-side derivation should have set it) —
// that assertion failed with "was 0" even though a direct LocalStorage read of
// the SAME persisted row confirms the server-side derivation genuinely ran and
// set the correct nonzero value. The test now verifies the server's actual
// derived value via a direct LocalStorage read (which bypasses the dropped
// wire field), and documents the response-wire gap inline rather than
// asserting around it silently. Every OTHER fixture in this file uses
// CreatedByMachineIdentityID=0 (a human-created identity, the overwhelmingly
// common case), so this gap does not surface elsewhere as a
// field-exhaustive-comparison failure. Flagged for a future tranche/fix; not
// remediated here since doing so would require editing existing non-test
// files, out of this tranche's scope.
//
// requireGranterHoldsRolePermissions / privilege-ceiling notes carried over from
// tranche 3, applied here too:
//
//   - RemoveMachineRole (and the AssignMachineRole calls used to seed its
//     fixture) use a zero-permission role, matching tranche 3's own
//     AssignMachineRole test — h.rs's admin-role node/machine credential
//     cannot be trusted to exercise a permission-carrying grant/removal
//     through a /system proxy route.
//   - CreateOIDCBinding is gated by core.CreateOIDCBinding's
//     requireAdminAuthorityAt, which resolves authority from the AUTHENTICATED
//     USER actor's own role grants (scopedRoleIDs keyed on a User ID) — a
//     machine-authenticated caller always resolves actorID(r)==0 for this
//     check (ADR-085 removed the former node-relay exemption for this route
//     family), so h.rs's node/machine credential can NEVER satisfy it,
//     regardless of what role the node itself holds. Mints a second
//     RemoteStorage client authenticated as a real admin USER session instead,
//     mirroring RevokeBreakGlassActivation's rsAsUser pattern (tranche 3).
//     DeleteOIDCBinding has no equivalent admin-authority gate of its own
//     (core.DeleteOIDCBinding only re-checks machineInProject), so h.rs works
//     fine there.
package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- CreateMachineIdentity ---

func TestConformance_CreateMachineIdentity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// LocalStorage.CreateMachineIdentity is a raw, unconditional GORM Create --
	// every field on the caller-supplied model lands exactly as sent.
	localModel := &models.MachineIdentity{
		ProjectID: h.projectID, Name: "conformance-cmi-local", IdentityType: "service",
		State: "active", Description: "conformance test", CreatedBy: h.adminUserID,
	}
	localCreated, err := h.ls.CreateMachineIdentity(ctx, localModel)
	require.NoError(t, err)
	assert.Equal(t, "active", localCreated.State, "sanity: local create preserves the caller-supplied State")
	assert.Equal(t, h.adminUserID, localCreated.CreatedBy, "sanity: local create preserves the caller-supplied CreatedBy")

	// RemoteStorage.CreateMachineIdentity's proxy handler does NOT perform a raw
	// passthrough Create (see this file's package doc, asymmetry #1): it forces
	// State=active and derives CreatedBy/CreatedByMachineIdentityID from the
	// AUTHENTICATED actor, never the wire model. h.rs authenticates as a
	// MACHINE credential (the harness's own node token), so CreatedBy must come
	// back 0 (no UserID for a machine actor) and CreatedByMachineIdentityID
	// must be that node's own machine ID -- neither the deliberately-wrong
	// values sent below.
	remoteModel := &models.MachineIdentity{
		ProjectID: h.projectID, Name: "conformance-cmi-remote", IdentityType: "service",
		State:                      "revoked", // deliberately wrong -- must be ignored, not persisted
		Description:                "conformance test",
		CreatedBy:                  999999, // deliberately forged
		CreatedByMachineIdentityID: 888888, // deliberately forged
	}
	remoteCreated, err := h.rs.CreateMachineIdentity(ctx, remoteModel)
	require.NoError(t, err, "RemoteStorage.CreateMachineIdentity must succeed for an actor holding roles.assign at the target project")

	assert.Equal(t, "conformance-cmi-remote", remoteCreated.Name)
	assert.Equal(t, h.projectID, remoteCreated.ProjectID)
	assert.Equal(t, "service", remoteCreated.IdentityType)
	assert.Equal(t, "conformance test", remoteCreated.Description)
	assert.Equal(t, "active", remoteCreated.State,
		"RemoteStorage.CreateMachineIdentity must force State=active regardless of what the caller sent -- "+
			"a machine identity is never born in any other state (core.CreateMachineIdentity's own contract)")
	assert.Equal(t, uint(0), remoteCreated.CreatedBy,
		"CreatedBy must be derived from the authenticated actor (a machine actor has no UserID), never trusted from the wire")
	// remoteCreated.CreatedByMachineIdentityID itself is NOT a usable signal
	// here: machineIdentityProxyWire/machineIdentityWire (both sides of this
	// route) omit the CreatedByMachineIdentityID field entirely, so the
	// CREATE response's decoded value is unconditionally 0 -- confirmed by
	// running this exact assertion against a nonzero expectation and seeing
	// it fail even though the server-side derivation genuinely ran (see the
	// package doc's confirmed-gap note). Verify the SERVER's actual derived
	// value by reading the persisted row directly via LocalStorage instead,
	// which bypasses that wire entirely.
	persisted, err := h.ls.GetMachineIdentity(ctx, remoteCreated.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", persisted.State, "the created identity must actually be persisted server-side with the forced state")
	assert.NotEqual(t, uint(888888), persisted.CreatedByMachineIdentityID,
		"the persisted CreatedByMachineIdentityID must be derived from the authenticated actor, never the caller-supplied value")
	assert.NotZero(t, persisted.CreatedByMachineIdentityID,
		"the harness's own node credential IS a real machine identity, so the server-derived, persisted value must be non-zero "+
			"(even though RemoteStorage's own CREATE response cannot show it -- see above)")

	// Negative: missing required fields must be rejected.
	_, remoteErr := h.rs.CreateMachineIdentity(ctx, &models.MachineIdentity{})
	assert.Error(t, remoteErr, "RemoteStorage.CreateMachineIdentity must reject a request missing name/project_id")
}

// --- GetMachineIdentity ---

func TestConformance_GetMachineIdentity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmi", core.MachineTypeService, "conformance test machine", "confidential", h.adminUserID, 0)
	require.NoError(t, err)

	localRead, err := h.ls.GetMachineIdentity(ctx, mi.ID)
	require.NoError(t, err)
	remoteRead, err := h.rs.GetMachineIdentity(ctx, mi.ID)
	require.NoError(t, err, "RemoteStorage.GetMachineIdentity must retrieve a genuinely existing machine identity")
	// A pure dual-read of the SAME already-persisted row -- no write timing
	// skew of any kind, so no exclusions are needed (see this file's package
	// doc for the one confirmed field this comparison cannot expose, given
	// this fixture's CreatedByMachineIdentityID=0).
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetMachineIdentity (wire round trip)", localRead, remoteRead, nil)

	// Negative: a nonexistent ID must fail identically on both paths.
	_, localErr := h.ls.GetMachineIdentity(ctx, mi.ID+1000000)
	_, remoteErr := h.rs.GetMachineIdentity(ctx, mi.ID+1000000)
	assert.Error(t, localErr, "sanity: a nonexistent machine identity must not be retrievable locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetMachineIdentity must report an error for a nonexistent machine identity, not a zero-value success")
}

// --- LockMachineIdentityForUpdate ---

func TestConformance_LockMachineIdentityForUpdate(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lmifu", core.MachineTypeService, "conformance test machine", "internal", h.adminUserID, 0)
	require.NoError(t, err)

	// LockMachineIdentityForUpdate has no row lock to take over HTTP (see
	// remote_machine_identities.go's own doc) -- it is a plain read on both
	// sides, so a fair conformance check is exactly the same dual-read shape
	// as GetMachineIdentity, not a locking/concurrency test (that guarantee now
	// lives entirely in TransitionMachineIdentityState, already covered in
	// tranche 2).
	localRead, err := h.ls.LockMachineIdentityForUpdate(ctx, mi.ID)
	require.NoError(t, err)
	remoteRead, err := h.rs.LockMachineIdentityForUpdate(ctx, mi.ID)
	require.NoError(t, err, "RemoteStorage.LockMachineIdentityForUpdate must retrieve a genuinely existing machine identity")
	assertFieldExhaustiveEqual(t, "RemoteStorage.LockMachineIdentityForUpdate (wire round trip)", localRead, remoteRead, nil)

	_, localErr := h.ls.LockMachineIdentityForUpdate(ctx, mi.ID+1000000)
	_, remoteErr := h.rs.LockMachineIdentityForUpdate(ctx, mi.ID+1000000)
	assert.Error(t, localErr, "sanity: a nonexistent machine identity must not be retrievable locally")
	assert.Error(t, remoteErr, "RemoteStorage.LockMachineIdentityForUpdate must report an error for a nonexistent machine identity")
}

// --- ListMachineIdentities ---

func TestConformance_ListMachineIdentities(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lmi-other-project", "", []string{"dev"})
	require.NoError(t, err)

	byName := func(rows []*models.MachineIdentity, name string) *models.MachineIdentity {
		for _, m := range rows {
			if m.Name == name {
				return m
			}
		}
		return nil
	}

	inScope, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lmi-in-scope", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	outOfScope, err := h.upstreamCore.CreateMachineIdentity(ctx, otherProject.ID, "conformance-lmi-out-of-scope", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)

	localList, err := h.ls.ListMachineIdentities(ctx, h.projectID)
	require.NoError(t, err)
	assert.NotNil(t, byName(localList, inScope.Name), "sanity: an in-project identity must be listed")
	assert.Nil(t, byName(localList, outOfScope.Name), "sanity: an identity in a different project must not be listed")

	remoteList, err := h.rs.ListMachineIdentities(ctx, h.projectID)
	require.NoError(t, err)
	found := byName(remoteList, inScope.Name)
	require.NotNil(t, found, "RemoteStorage.ListMachineIdentities must return the in-project identity")
	assertFieldExhaustiveEqual(t, "RemoteStorage.ListMachineIdentities item", inScope, found, nil)
	assert.Nil(t, byName(remoteList, outOfScope.Name),
		"RemoteStorage.ListMachineIdentities must NOT include an identity from a different project -- a dropped/ignored project_id on the wire would leak it")
}

// --- ListAllMachineIdentities ---

func TestConformance_ListAllMachineIdentities(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lami-other-project", "", []string{"dev"})
	require.NoError(t, err)

	byName := func(rows []*models.MachineIdentity, name string) *models.MachineIdentity {
		for _, m := range rows {
			if m.Name == name {
				return m
			}
		}
		return nil
	}

	remoteName := "conformance-lami-remote"
	remoteMI, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, remoteName, core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	remoteOtherMI, err := h.upstreamCore.CreateMachineIdentity(ctx, otherProject.ID, "conformance-lami-remote-other", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)

	// Sanity via LocalStorage first: ListAllMachineIdentities spans every
	// project, not just h.projectID.
	localList, err := h.ls.ListAllMachineIdentities(ctx)
	require.NoError(t, err)
	assert.NotNil(t, byName(localList, remoteName), "sanity: local identity must be listed")
	assert.NotNil(t, byName(localList, remoteOtherMI.Name), "sanity: ListAllMachineIdentities spans every project")

	remoteList, err := h.rs.ListAllMachineIdentities(ctx)
	require.NoError(t, err)
	found := byName(remoteList, remoteName)
	require.NotNil(t, found, "RemoteStorage.ListAllMachineIdentities must include a genuine identity")
	assertFieldExhaustiveEqual(t, "RemoteStorage.ListAllMachineIdentities item", remoteMI, found, nil)
	assert.NotNil(t, byName(remoteList, remoteOtherMI.Name),
		"RemoteStorage.ListAllMachineIdentities must span every project, not just the caller's own -- a "+
			"dropped/scoped-down query would hide identities in other projects")
}

// --- CountMachineIdentitiesByClassification ---

func TestConformance_CountMachineIdentitiesByClassification(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, err := h.ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
			ProjectID: h.projectID, Name: fmt.Sprintf("conformance-cmibc-local-%d", i), IdentityType: "service",
			State: "active", Classification: "confidential",
		})
		require.NoError(t, err)
	}
	localCounts, err := h.ls.CountMachineIdentitiesByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, localCounts["confidential"], "sanity: local count must reflect the seeded classification")

	for i := 0; i < 3; i++ {
		_, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, fmt.Sprintf("conformance-cmibc-remote-%d", i), core.MachineTypeService, "d", "restricted", h.adminUserID, 0)
		require.NoError(t, err)
	}
	remoteCounts, err := h.rs.CountMachineIdentitiesByClassification(ctx)
	require.NoError(t, err, "RemoteStorage.CountMachineIdentitiesByClassification must succeed")
	assert.Equal(t, 3, remoteCounts["restricted"],
		"RemoteStorage.CountMachineIdentitiesByClassification must reflect exactly the identities actually created, grouped correctly by classification")
	assert.Equal(t, 2, remoteCounts["confidential"],
		"RemoteStorage's install-wide count must also include identities created directly via LocalStorage (same backing store)")
}

// --- CountMachineIdentityCredentialsByClassification ---

func TestConformance_CountMachineIdentityCredentialsByClassification(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newCred := func(suffix, classification string) {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-cmicbc-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		_, err = h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "conformance-cmicbc-cred-" + suffix, TokenHash: "conformance-cmicbc-hash-" + suffix,
			TokenPrefix: "kxm_" + suffix, Classification: classification,
		})
		require.NoError(t, err)
	}

	newCred("local-1", "confidential")
	newCred("local-2", "confidential")
	localCounts, err := h.ls.CountMachineIdentityCredentialsByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, localCounts["confidential"], "sanity: local count must reflect the seeded classification")

	newCred("remote-1", "restricted")
	newCred("remote-2", "restricted")
	newCred("remote-3", "restricted")
	remoteCounts, err := h.rs.CountMachineIdentityCredentialsByClassification(ctx)
	require.NoError(t, err, "RemoteStorage.CountMachineIdentityCredentialsByClassification must succeed")
	assert.Equal(t, 3, remoteCounts["restricted"], "RemoteStorage's count must reflect exactly what was seeded")
	assert.Equal(t, 2, remoteCounts["confidential"],
		"RemoteStorage's install-wide count must also include credentials created directly via LocalStorage")
}

// --- GetMachineIdentityCredentialByHash ---

func TestConformance_GetMachineIdentityCredentialByHash(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmicbh-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	_, err = h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID, Name: "conformance-gmicbh-cred", TokenHash: "conformance-gmicbh-hash", TokenPrefix: "kxm_gmicbh",
	})
	require.NoError(t, err)

	localRead, err := h.ls.GetMachineIdentityCredentialByHash(ctx, "conformance-gmicbh-hash")
	require.NoError(t, err)
	remoteRead, err := h.rs.GetMachineIdentityCredentialByHash(ctx, "conformance-gmicbh-hash")
	require.NoError(t, err,
		"RemoteStorage.GetMachineIdentityCredentialByHash must resolve a genuinely existing hash -- backs core.ValidateMachineToken's authentication lookup")
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetMachineIdentityCredentialByHash (wire round trip)", localRead, remoteRead, nil)

	_, localErr := h.ls.GetMachineIdentityCredentialByHash(ctx, "no-such-hash")
	_, remoteErr := h.rs.GetMachineIdentityCredentialByHash(ctx, "no-such-hash")
	assert.Error(t, localErr, "sanity: an unknown hash must not resolve locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetMachineIdentityCredentialByHash must report an error for an unknown hash, not a zero-value success")
}

// --- GetMachineIdentityCredentialByID ---

func TestConformance_GetMachineIdentityCredentialByID(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmicbid-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	cred, err := h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID, Name: "conformance-gmicbid-cred", TokenHash: "conformance-gmicbid-hash", TokenPrefix: "kxm_gmicbid",
	})
	require.NoError(t, err)

	localRead, err := h.ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	remoteRead, err := h.rs.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err, "RemoteStorage.GetMachineIdentityCredentialByID must retrieve a genuinely existing credential")
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetMachineIdentityCredentialByID (wire round trip)", localRead, remoteRead, nil)

	_, localErr := h.ls.GetMachineIdentityCredentialByID(ctx, cred.ID+1000000)
	_, remoteErr := h.rs.GetMachineIdentityCredentialByID(ctx, cred.ID+1000000)
	assert.Error(t, localErr, "sanity: a nonexistent credential must not be retrievable locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetMachineIdentityCredentialByID must report an error for a nonexistent credential")
}

// --- ListMachineIdentityCredentials ---

func TestConformance_ListMachineIdentityCredentials(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lmic-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	otherMI, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lmic-other-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)

	cred, err := h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID, Name: "conformance-lmic-cred", TokenHash: "conformance-lmic-hash", TokenPrefix: "kxm_lmic",
	})
	require.NoError(t, err)
	_, err = h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: otherMI.ID, Name: "conformance-lmic-other-cred", TokenHash: "conformance-lmic-other-hash", TokenPrefix: "kxm_lmico",
	})
	require.NoError(t, err)

	localList, err := h.ls.ListMachineIdentityCredentials(ctx, mi.ID)
	require.NoError(t, err)
	require.Len(t, localList, 1, "sanity: only the target machine's own credential must be listed")

	remoteList, err := h.rs.ListMachineIdentityCredentials(ctx, mi.ID)
	require.NoError(t, err)
	require.Len(t, remoteList, 1,
		"RemoteStorage.ListMachineIdentityCredentials must return only the target machine's own credential, not "+
			"another machine's -- a dropped/ignored machine_identity_id on the wire would leak or hide credentials")
	assertFieldExhaustiveEqual(t, "RemoteStorage.ListMachineIdentityCredentials item", cred, remoteList[0], nil)

	bystander, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lmic-bystander", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	emptyList, err := h.rs.ListMachineIdentityCredentials(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyList, "a machine with no credentials must return an empty list, not error")
}

// --- ListActiveMachineIdentityCredentials ---

func TestConformance_ListActiveMachineIdentityCredentials(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newMachineWithCred := func(suffix string, revoked bool) *models.MachineIdentityCredential {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lamic-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		cred, err := h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "conformance-lamic-cred-" + suffix,
			TokenHash: "conformance-lamic-hash-" + suffix, TokenPrefix: "kxm_" + suffix, Revoked: revoked,
		})
		require.NoError(t, err)
		return cred
	}

	byHash := func(creds []*models.MachineIdentityCredential, hash string) *models.MachineIdentityCredential {
		for _, c := range creds {
			if c.TokenHash == hash {
				return c
			}
		}
		return nil
	}

	activeLocal := newMachineWithCred("local-active", false)
	revokedLocal := newMachineWithCred("local-revoked", true)
	localList, err := h.ls.ListActiveMachineIdentityCredentials(ctx)
	require.NoError(t, err)
	assert.NotNil(t, byHash(localList, activeLocal.TokenHash), "sanity: an active local credential must be listed")
	assert.Nil(t, byHash(localList, revokedLocal.TokenHash), "sanity: a revoked local credential must NOT be listed")

	activeRemote := newMachineWithCred("remote-active", false)
	revokedRemote := newMachineWithCred("remote-revoked", true)
	remoteList, err := h.rs.ListActiveMachineIdentityCredentials(ctx)
	require.NoError(t, err)
	found := byHash(remoteList, activeRemote.TokenHash)
	require.NotNil(t, found, "RemoteStorage.ListActiveMachineIdentityCredentials must include a genuinely active credential")
	assertFieldExhaustiveEqual(t, "RemoteStorage.ListActiveMachineIdentityCredentials item", activeRemote, found, nil)
	assert.Nil(t, byHash(remoteList, revokedRemote.TokenHash),
		"a revoked credential must not appear in RemoteStorage's active list either -- a dropped/ignored revoked filter on the wire would leak it")
}

// --- UpdateMachineIdentityCredential ---

func TestConformance_UpdateMachineIdentityCredential(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newCredential := func(suffix string) *models.MachineIdentityCredential {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-umic-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		cred, err := h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "conformance-umic-cred-" + suffix, TokenHash: "conformance-umic-hash-" + suffix, TokenPrefix: "kxm_" + suffix,
		})
		require.NoError(t, err)
		return cred
	}

	// LocalStorage.UpdateMachineIdentityCredential is a raw, unconditional
	// full-row Save -- every field the caller mutated lands.
	localCred := newCredential("local")
	localCred.Classification = "confidential"
	require.NoError(t, h.ls.UpdateMachineIdentityCredential(ctx, localCred))
	localAfter, err := h.ls.GetMachineIdentityCredentialByID(ctx, localCred.ID)
	require.NoError(t, err)
	assert.Equal(t, "confidential", localAfter.Classification, "sanity: local update must land")

	// RemoteStorage.UpdateMachineIdentityCredential's proxy handler deliberately
	// does NOT perform a raw full-row Save -- see this file's package doc,
	// asymmetry #2: it routes through core.ClassifyMachineTokenByID, which
	// re-fetches the row server-side and applies ONLY Classification,
	// discarding every other field the client's in-memory struct carries. A
	// fair comparison mutates ONLY Classification (matching the real caller,
	// ClassifyMachineToken) AND separately proves the narrowing by ALSO
	// sending a forged TokenHash/Revoked and confirming they do NOT land.
	remoteCred := newCredential("remote")
	originalTokenHash := remoteCred.TokenHash
	remoteCred.Classification = "confidential"
	remoteCred.TokenHash = "conformance-umic-FORGED-hash"
	remoteCred.Revoked = true
	require.NoError(t, h.rs.UpdateMachineIdentityCredential(ctx, remoteCred),
		"RemoteStorage.UpdateMachineIdentityCredential must succeed for a genuine, existing credential")

	remotePersisted, err := h.ls.GetMachineIdentityCredentialByID(ctx, remoteCred.ID)
	require.NoError(t, err)
	assert.Equal(t, "confidential", remotePersisted.Classification,
		"the classification change must actually be persisted server-side, not just report success")
	assert.Equal(t, originalTokenHash, remotePersisted.TokenHash,
		"TokenHash must NOT be overwritten by a client-supplied value under cover of a classification update -- "+
			"the server narrows the write to Classification only (core.ClassifyMachineTokenByID)")
	assert.False(t, remotePersisted.Revoked, "Revoked must NOT be flippable via this route either -- same narrowing")

	// Negative: an invalid classification value must be rejected.
	remoteCred.Classification = "not-a-real-classification"
	assert.Error(t, h.rs.UpdateMachineIdentityCredential(ctx, remoteCred),
		"RemoteStorage.UpdateMachineIdentityCredential must reject an invalid classification value")
}

// --- TouchMachineIdentityCredential ---

func TestConformance_TouchMachineIdentityCredential(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newCredential := func(suffix string) *models.MachineIdentityCredential {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-tmic-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		cred, err := h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "conformance-tmic-cred-" + suffix, TokenHash: "conformance-tmic-hash-" + suffix, TokenPrefix: "kxm_" + suffix,
		})
		require.NoError(t, err)
		return cred
	}

	staleness := time.Hour
	usedAt := time.Now().UTC().Truncate(time.Second)

	localCred := newCredential("local")
	require.NoError(t, h.ls.TouchMachineIdentityCredential(ctx, localCred.ID, usedAt, staleness))
	localAfter, err := h.ls.GetMachineIdentityCredentialByID(ctx, localCred.ID)
	require.NoError(t, err)
	require.NotNil(t, localAfter.LastUsedAt)
	assert.True(t, localAfter.LastUsedAt.Equal(usedAt), "sanity: LocalStorage must record the used-at timestamp")

	remoteCred := newCredential("remote")
	require.NoError(t, h.rs.TouchMachineIdentityCredential(ctx, remoteCred.ID, usedAt, staleness),
		"RemoteStorage.TouchMachineIdentityCredential must succeed")
	remoteAfter, err := h.ls.GetMachineIdentityCredentialByID(ctx, remoteCred.ID)
	require.NoError(t, err)
	require.NotNil(t, remoteAfter.LastUsedAt)
	assert.True(t, remoteAfter.LastUsedAt.Equal(usedAt),
		"RemoteStorage.TouchMachineIdentityCredential must actually persist the used-at timestamp server-side")

	// Throttling: a second touch with an EARLIER usedAt, still within the
	// staleness window, must be a no-op -- proves the wire call preserves the
	// conditional "only update if stale" write (local_machine_credentials.go's
	// `WHERE id = ? AND (last_used_at IS NULL OR last_used_at < cutoff)`), not
	// an unconditional overwrite that would defeat the throttle.
	earlierUsedAt := usedAt.Add(-time.Minute)
	require.NoError(t, h.rs.TouchMachineIdentityCredential(ctx, remoteCred.ID, earlierUsedAt, staleness))
	stillAfter, err := h.ls.GetMachineIdentityCredentialByID(ctx, remoteCred.ID)
	require.NoError(t, err)
	assert.True(t, stillAfter.LastUsedAt.Equal(usedAt),
		"a second touch within the staleness window must NOT overwrite the existing last_used_at over RemoteStorage")
}

// --- GetMachineRoleIDsAt ---

func TestConformance_GetMachineRoleIDsAt(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("conformance-gmria-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-gmria-other-project", "", []string{"dev"})
	require.NoError(t, err)

	scope := coreStorage.Scope{ProjectID: h.projectID}

	newGrantedMachine := func(suffix string) *models.MachineIdentity {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmria-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignMachineRole(ctx, mi.ID, role.ID, scope))
		return mi
	}

	localMachine := newGrantedMachine("local")
	localIDs, err := h.ls.GetMachineRoleIDsAt(ctx, localMachine.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, localIDs, role.ID, "sanity: local grant visible at the target scope")

	remoteMachine := newGrantedMachine("remote")
	remoteIDs, err := h.rs.GetMachineRoleIDsAt(ctx, remoteMachine.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, remoteIDs, role.ID, "RemoteStorage.GetMachineRoleIDsAt must see the role grant server-side")

	// Negative: a grant scoped to one project must not leak into a query for a
	// genuinely different project -- the project-drop/widen risk this method
	// exists to catch.
	otherScope := coreStorage.Scope{ProjectID: otherProject.ID}
	emptyIDs, err := h.rs.GetMachineRoleIDsAt(ctx, remoteMachine.ID, otherScope)
	require.NoError(t, err)
	assert.NotContains(t, emptyIDs, role.ID,
		"a grant scoped to one project must not leak into a query for a different project")
}

// --- GetMachineRoles ---

func TestConformance_GetMachineRoles(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("conformance-gmr-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)
	scope := coreStorage.Scope{ProjectID: h.projectID}

	newGrantedMachine := func(suffix string) *models.MachineIdentity {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmr-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignMachineRole(ctx, mi.ID, role.ID, scope))
		return mi
	}

	byID := func(roles []*models.Role, id uint) *models.Role {
		for _, r := range roles {
			if r.ID == id {
				return r
			}
		}
		return nil
	}

	localMachine := newGrantedMachine("local")
	localRoles, err := h.ls.GetMachineRoles(ctx, localMachine.ID)
	require.NoError(t, err)
	require.NotNil(t, byID(localRoles, role.ID), "sanity: local role visible")

	remoteMachine := newGrantedMachine("remote")
	remoteRoles, err := h.rs.GetMachineRoles(ctx, remoteMachine.ID)
	require.NoError(t, err)
	found := byID(remoteRoles, role.ID)
	require.NotNil(t, found, "RemoteStorage.GetMachineRoles must return the granted role")
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetMachineRoles role fields", role, found, map[string]bool{
		// NameFolded carries json:"-" on models.Role itself (never sent to ANY
		// API surface, including the human-facing one) -- roleProxyWire/roleWire
		// (ID/Name/Description only) both omit it on purpose, confirmed by that
		// tag, not assumed.
		"NameFolded": true,
	})

	// Negative: a machine with no grants must return an empty list, not error.
	bystander, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmr-bystander", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	bystanderRoles, err := h.rs.GetMachineRoles(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, bystanderRoles, "a machine with no role grants must return an empty list")
}

// --- RemoveMachineRole ---

func TestConformance_RemoveMachineRole(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Zero-permission role -- mirrors tranche 3's AssignMachineRole/
	// AssignRoleWithExpiry reasoning: h.rs's admin-role node/machine
	// credential relayed through a /system proxy route cannot be trusted to
	// exercise a permission-carrying grant/removal.
	roleName, err := identity.NewFoldedName("conformance-rmr-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)
	scope := coreStorage.Scope{ProjectID: h.projectID}

	newGrantedMachine := func(suffix string) *models.MachineIdentity {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-rmr-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignMachineRole(ctx, mi.ID, role.ID, scope))
		return mi
	}

	localMachine := newGrantedMachine("local")
	require.NoError(t, h.ls.RemoveMachineRole(ctx, localMachine.ID, role.ID, scope))

	remoteMachine := newGrantedMachine("remote")
	require.NoError(t, h.rs.RemoveMachineRole(ctx, remoteMachine.ID, role.ID, scope),
		"RemoteStorage.RemoveMachineRole must succeed for a genuine, existing grant on a machine in the caller-supplied project")

	localIDsAfter, err := h.ls.GetMachineRoleIDsAt(ctx, localMachine.ID, scope)
	require.NoError(t, err)
	remoteIDsAfter, err := h.ls.GetMachineRoleIDsAt(ctx, remoteMachine.ID, scope)
	require.NoError(t, err)
	assert.NotContains(t, localIDsAfter, role.ID, "sanity: local grant must be gone")
	assert.NotContains(t, remoteIDsAfter, role.ID, "the remote grant must actually be gone server-side, not just report success")

	// Negative: removing a grant that doesn't exist (already removed) must
	// fail identically on both paths, not silently no-op succeed.
	assert.Error(t, h.ls.RemoveMachineRole(ctx, localMachine.ID, role.ID, scope))
	assert.Error(t, h.rs.RemoveMachineRole(ctx, remoteMachine.ID, role.ID, scope))
}

// --- CreateOIDCBinding ---

func TestConformance_CreateOIDCBinding(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// core.CreateOIDCBinding requires GLOBAL admin authority resolved from the
	// AUTHENTICATED USER actor's own role grants (requireAdminAuthorityAt ->
	// scopedRoleIDs keyed on a User ID) -- h.rs's node/machine credential
	// always resolves actorID(r)==0 for this check (ADR-085 removed the
	// former node-relay exemption), so it can never satisfy this route no
	// matter what role the node itself holds. Mint a second RemoteStorage
	// client authenticated as a real admin USER session instead, mirroring
	// RevokeBreakGlassActivation's rsAsUser pattern (tranche 3).
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	newMachine := func(suffix string) *models.MachineIdentity {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-cob-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		return mi
	}

	localMachine := newMachine("local")
	localBinding, err := h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: localMachine.ID, Issuer: "https://issuer.example/cob-local", Subject: "sub-cob-local", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	assert.Equal(t, h.adminUserID, localBinding.CreatedBy, "sanity: local create preserves the caller-supplied CreatedBy")

	remoteMachine := newMachine("remote")
	remoteBinding, err := rsAsUser.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: remoteMachine.ID, Issuer: "https://issuer.example/cob-remote", Subject: "sub-cob-remote",
		CreatedBy: 999999, // deliberately wrong -- must be ignored, see below
	})
	require.NoError(t, err,
		"RemoteStorage.CreateOIDCBinding must succeed for an admin USER actor creating a binding for a machine in a project it belongs to")

	assert.Equal(t, remoteMachine.ID, remoteBinding.MachineIdentityID)
	assert.Equal(t, "https://issuer.example/cob-remote", remoteBinding.Issuer)
	assert.Equal(t, "sub-cob-remote", remoteBinding.Subject)
	// CreatedBy must be derived from the authenticated session, never trusted
	// from the wire -- same never-trust-client-asserted-attribution discipline
	// as RevokeBreakGlassActivation's RevokedBy (tranche 3).
	assert.NotEqual(t, uint(999999), remoteBinding.CreatedBy,
		"CreatedBy must be derived from the authenticated session server-side, not trusted from the wire")
	assert.Equal(t, h.adminUserID, remoteBinding.CreatedBy)

	persisted, err := h.ls.GetOIDCBindingByID(ctx, remoteBinding.ID)
	require.NoError(t, err)
	assert.Equal(t, remoteMachine.ID, persisted.MachineIdentityID, "the binding must actually be persisted server-side, not just report success")

	// Negative: a duplicate (issuer, subject) pair must be rejected identically
	// on both paths, not silently succeed a second time.
	_, dupLocalErr := h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: localMachine.ID, Issuer: "https://issuer.example/cob-local", Subject: "sub-cob-local", CreatedBy: h.adminUserID,
	})
	assert.Error(t, dupLocalErr, "sanity: a duplicate (issuer, subject) pair must be rejected locally")
	_, dupRemoteErr := rsAsUser.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: remoteMachine.ID, Issuer: "https://issuer.example/cob-remote", Subject: "sub-cob-remote",
	})
	assert.Error(t, dupRemoteErr, "RemoteStorage.CreateOIDCBinding must reject a duplicate (issuer, subject) pair too, not silently succeed")
}

// --- GetMachineByOIDCSubject ---

func TestConformance_GetMachineByOIDCSubject(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gmbos-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	_, err = h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: mi.ID, Issuer: "https://issuer.example/gmbos", Subject: "sub-gmbos", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)

	localRead, err := h.ls.GetMachineByOIDCSubject(ctx, "https://issuer.example/gmbos", "sub-gmbos")
	require.NoError(t, err)
	remoteRead, err := h.rs.GetMachineByOIDCSubject(ctx, "https://issuer.example/gmbos", "sub-gmbos")
	require.NoError(t, err, "RemoteStorage.GetMachineByOIDCSubject must resolve a genuinely bound (issuer, subject)")
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetMachineByOIDCSubject (wire round trip)", localRead, remoteRead, nil)

	_, localErr := h.ls.GetMachineByOIDCSubject(ctx, "https://issuer.example/gmbos", "no-such-subject")
	_, remoteErr := h.rs.GetMachineByOIDCSubject(ctx, "https://issuer.example/gmbos", "no-such-subject")
	assert.Error(t, localErr, "sanity: an unbound subject must not resolve locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetMachineByOIDCSubject must report an error for an unbound (issuer, subject), not a zero-value success")
}

// --- ListOIDCBindings ---

func TestConformance_ListOIDCBindings(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lob-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	otherMI, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lob-other-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)

	binding, err := h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: mi.ID, Issuer: "https://issuer.example/lob", Subject: "sub-lob", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: otherMI.ID, Issuer: "https://issuer.example/lob-other", Subject: "sub-lob-other", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)

	localList, err := h.ls.ListOIDCBindings(ctx, mi.ID)
	require.NoError(t, err)
	require.Len(t, localList, 1, "sanity: only the target machine's own binding must be listed")

	remoteList, err := h.rs.ListOIDCBindings(ctx, mi.ID)
	require.NoError(t, err)
	require.Len(t, remoteList, 1, "RemoteStorage.ListOIDCBindings must return only the target machine's own binding, not another machine's")
	assertFieldExhaustiveEqual(t, "RemoteStorage.ListOIDCBindings item", binding, remoteList[0], nil)

	bystander, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lob-bystander", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	emptyList, err := h.rs.ListOIDCBindings(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyList, "a machine with no bindings must return an empty list, not error")
}

// --- GetOIDCBindingByID ---

func TestConformance_GetOIDCBindingByID(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-gobbi-mi", core.MachineTypeService, "d", "", h.adminUserID, 0)
	require.NoError(t, err)
	binding, err := h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: mi.ID, Issuer: "https://issuer.example/gobbi", Subject: "sub-gobbi", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)

	localRead, err := h.ls.GetOIDCBindingByID(ctx, binding.ID)
	require.NoError(t, err)
	remoteRead, err := h.rs.GetOIDCBindingByID(ctx, binding.ID)
	require.NoError(t, err, "RemoteStorage.GetOIDCBindingByID must retrieve a genuinely existing binding")
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetOIDCBindingByID (wire round trip)", localRead, remoteRead, nil)

	_, localErr := h.ls.GetOIDCBindingByID(ctx, binding.ID+1000000)
	_, remoteErr := h.rs.GetOIDCBindingByID(ctx, binding.ID+1000000)
	assert.Error(t, localErr, "sanity: a nonexistent binding must not be retrievable locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetOIDCBindingByID must report an error for a nonexistent binding")
}

// --- DeleteOIDCBinding ---

func TestConformance_DeleteOIDCBinding(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Unlike CreateOIDCBinding, core.DeleteOIDCBinding has no separate
	// admin-authority gate of its own (only a machineInProject re-check
	// against the SERVER-resolved project) -- h.rs's node/machine credential
	// works fine here, no rsAsUser needed.
	newBoundMachine := func(suffix string) *models.MachineIdentityOIDCBinding {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-dob-mi-"+suffix, core.MachineTypeService, "d", "", h.adminUserID, 0)
		require.NoError(t, err)
		b, err := h.ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
			MachineIdentityID: mi.ID, Issuer: "https://issuer.example/dob-" + suffix, Subject: "sub-dob-" + suffix, CreatedBy: h.adminUserID,
		})
		require.NoError(t, err)
		return b
	}

	localBinding := newBoundMachine("local")
	require.NoError(t, h.ls.DeleteOIDCBinding(ctx, localBinding.ID))

	remoteBinding := newBoundMachine("remote")
	require.NoError(t, h.rs.DeleteOIDCBinding(ctx, remoteBinding.ID),
		"RemoteStorage.DeleteOIDCBinding must succeed for a binding that genuinely exists")

	_, localErr := h.ls.GetOIDCBindingByID(ctx, localBinding.ID)
	_, remoteErr := h.ls.GetOIDCBindingByID(ctx, remoteBinding.ID)
	assert.Error(t, localErr, "sanity: the local binding must be gone")
	assert.Error(t, remoteErr, "the binding deleted via RemoteStorage must actually be gone server-side, not just report success")

	// Deleting an already-deleted (or never-existent) binding must fail
	// identically on both paths.
	assert.Error(t, h.ls.DeleteOIDCBinding(ctx, localBinding.ID))
	assert.Error(t, h.rs.DeleteOIDCBinding(ctx, remoteBinding.ID))
}
