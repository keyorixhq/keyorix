// remote_storage_conformance_tranche4_dynamic_rotation_test.go — issue #1808,
// tranche 4.
//
// Covers 10 of the assigned 12 methods spanning two source files:
//
//	remote_dynamic.go: CountActiveLeases, CountDynamicSecretConfigsByClassification,
//	GetDynamicSecretConfig, GetDynamicSecretLease, ListDynamicSecretConfigs,
//	ListDynamicSecretLeases, ListExpiredActiveLeases
//
//	remote_rotation_policies.go: DeleteRotationPolicy, GetRotationPolicy,
//	ListRotationPolicies
//
// (CreateDynamicSecretConfig/UpdateDynamicSecretConfig/
// TransitionDynamicSecretConfigDisabled/CreateDynamicSecretLease/
// UpdateDynamicSecretLease are NOT in this tranche's method list -- they are
// also hard `remoteUnsupported` stubs on RemoteStorage per the G80 liveness
// sweep, so every dynamic-secrets fixture below is seeded exclusively through
// h.ls, matching how those stubs already force every OTHER dynamic-secrets
// test in this repo to seed.)
//
// SKIPPED (not a fixture-cost skip -- a genuine, confirmed, currently-shipping
// wire bug found while writing this tranche, exactly the class of defect this
// harness exists to catch):
//
//   - CreateRotationPolicy, UpdateRotationPolicy: RemoteStorage.CreateRotationPolicy/
//     UpdateRotationPolicy (remote_rotation_policies.go) POST/PUT the caller's
//     *models.RotationPolicy directly via `rs.client.Post/Put(ctx, path, p)`,
//     which json.Marshal's it verbatim -- and models.RotationPolicy carries NO
//     json tags on Name/Scope/ProjectID/EnvironmentID/IntervalDays/
//     AlertDaysBefore/NotifyOnBreach/IsActive/CreatedBy (only RotationState/
//     LastRotationError/LastStateAt do), so it marshals as PascalCase keys
//     ("IntervalDays", "ProjectID", ...). The server-side handler
//     (rotation_policies_handler.go's Create/Update) decodes into a reqBody
//     struct tagged with snake_case keys ("interval_days", "project_id", ...).
//     encoding/json's fallback case-insensitive field match (bytes.EqualFold)
//     cannot bridge "IntervalDays" to "interval_days" -- the strings differ by
//     more than case (an inserted underscore), so EqualFold never matches for
//     any multi-word field. The result: reqBody.IntervalDays/ProjectID/
//     EnvironmentID/AlertDaysBefore/NotifyOnBreach ALL silently decode to their
//     zero values regardless of what the caller actually set, and
//     reqBody.IntervalDays == 0 then trips `validate:"required,min=1,max=365"`
//     -- confirmed empirically (not theorized): every real attempt below
//     failed with the server's own 400 `{"field":"interval_days","message":
//     "must be at least 1"}`, for a caller that set IntervalDays: 30. This
//     means CreateRotationPolicy/UpdateRotationPolicy are BROKEN over
//     RemoteStorage unconditionally -- every storage.type: remote deployment's
//     downstream server fails every rotation-policy create/update a real user
//     performs through it, not an edge case. Filed as a critical, human-reachable
//     finding for immediate follow-up rather than fixed here: fixing it means
//     editing remote_rotation_policies.go and/or rotation_policies_handler.go,
//     both existing files this tranche's own scope forbids touching (only ONE
//     new file may be added). A real passing conformance test for either method
//     cannot be written until that fix lands -- writing one now would either be
//     a tautological test of the ALREADY-KNOWN-BROKEN 400 response (not what
//     this harness is for) or would require modifying the very files this task
//     says not to touch.
//
// Fixture pattern: the 7 remote_dynamic.go methods and GetRotationPolicy/
// ListRotationPolicies are pure reads (or install-wide aggregates) with no
// server-side business logic that could legitimately mutate a result -- for
// these, a SINGLE shared fixture set is seeded via h.ls and then read through
// BOTH h.ls.M(x) and h.rs.M(x), exactly like remote_storage_conformance_test.go's
// GetSecretByName/LockUserForUpdate. This is a strictly stronger check than
// two independent "local scenario"/"remote scenario" fixtures would be: it
// directly tests the harness's own stated property (RemoteStorage.M(x) against
// the SAME backing store LocalStorage.M(x) sees), rather than two isolated
// scenarios that could each pass without ever proving the two facades agree.
//
// CreateRotationPolicy/UpdateRotationPolicy/DeleteRotationPolicy are the
// mutating exception, and use the dual local-scenario/remote-scenario fixture
// pattern established in tranches 2 and 3 (independent rows per facade, so one
// path's write can never contaminate the other's comparison).
//
// CreateRotationPolicy and UpdateRotationPolicy both route through the
// human-facing REST handlers (rotation_policies_handler.go), which run the
// FULL core.CreateRotationPolicy/UpdateRotationPolicy business logic -- NOT a
// raw storage passthrough like the dynamic-secrets /system proxy routes above.
// CreatedBy in particular is always derived server-side from the authenticated
// caller's own session (userCtx.Username), discarding whatever CreatedBy the
// wire model carries -- see CreateRotationPolicy's own comment below for the
// confirmed call site.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// uintPtr is a small local helper for the *uint-typed scope fields
// (RotationPolicy.ProjectID/EnvironmentID, ListRotationPolicies' parameters)
// used repeatedly below.
func uintPtr(v uint) *uint { return &v }

// --- GetDynamicSecretConfig ---

func TestConformance_GetDynamicSecretConfig(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	cfg, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "conformance-gdsc-config", ProjectID: h.projectID, EnvironmentID: h.environmentID,
		BackendType: "postgres",
		// AdminDSNEnc/AdminDSNMeta: opaque test ciphertext bytes -- the whole point
		// of this proxy tree (dynamic_secrets_proxy.go's package doc) is that this
		// crosses the wire byte-for-byte. models.DynamicSecretConfig tags these
		// `json:"-"`, but that tag is irrelevant to assertFieldExhaustiveEqual (a
		// reflection-based comparator over the Go struct, not a JSON marshal of the
		// model) -- the actual wire DTO (dynamicSecretConfigWire /
		// dynamicSecretConfigProxyWire) carries its own explicit
		// `json:"admin_dsn_enc,omitempty"` tag that puts these bytes on the wire.
		AdminDSNEnc:       []byte("conformance-ciphertext-admin-dsn"),
		AdminDSNMeta:      []byte("conformance-admin-dsn-meta-v1"),
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600,
		MaxTTLSeconds:     86400,
		MaxActiveLeases:   5,
		Classification:    "confidential",
		CreatedBy:         "conformance-test",
	})
	require.NoError(t, err)

	// Both reads fetch the identical DB row (same backing store) -- no server-side
	// business logic can legitimately mutate a read, so a clean field-exhaustive
	// comparison, same reasoning as GetSecretByName
	// (remote_storage_conformance_test.go).
	localOut, err := h.ls.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err, "RemoteStorage.GetDynamicSecretConfig must succeed for a config that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetDynamicSecretConfig (RemoteStorage vs LocalStorage, same row)",
		localOut, remoteOut, map[string]bool{})

	_, err = h.rs.GetDynamicSecretConfig(ctx, cfg.ID+987654)
	assert.Error(t, err, "RemoteStorage.GetDynamicSecretConfig must fail for a config that does not exist")
}

// --- GetDynamicSecretLease ---

func TestConformance_GetDynamicSecretLease(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	cfg, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "conformance-gdsl-config", ProjectID: h.projectID, EnvironmentID: h.environmentID,
		BackendType: "postgres", CreationTemplate: "-- noop", DefaultTTLSeconds: 3600,
		MaxTTLSeconds: 86400, MaxActiveLeases: 5, CreatedBy: "conformance-test",
	})
	require.NoError(t, err)

	revokedAt := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)
	lease, err := h.ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: cfg.ID, LeaseID: "conformance-gdsl-lease-id", ProjectID: h.projectID,
		EnvironmentID: h.environmentID, RoleName: "conformance-gdsl-role",
		// CredentialEnc/CredentialMeta: same reasoning as AdminDSNEnc/AdminDSNMeta
		// above -- opaque ciphertext test bytes, deliberately exercised because
		// dynamicSecretLeaseWire/dynamicSecretLeaseProxyWire carry them explicitly.
		CredentialEnc:  []byte("conformance-cred-ciphertext"),
		CredentialMeta: []byte("conformance-cred-meta-v1"),
		Status:         "revoked",
		RevokeReason:   "conformance test revoke",
		IssuedAt:       time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		ExpiresAt:      time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		RevokedAt:      &revokedAt,
	})
	require.NoError(t, err)

	localOut, err := h.ls.GetDynamicSecretLease(ctx, lease.LeaseID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetDynamicSecretLease(ctx, lease.LeaseID)
	require.NoError(t, err, "RemoteStorage.GetDynamicSecretLease must succeed for a lease that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetDynamicSecretLease (RemoteStorage vs LocalStorage, same row)",
		localOut, remoteOut, map[string]bool{})

	_, err = h.rs.GetDynamicSecretLease(ctx, "conformance-gdsl-does-not-exist")
	assert.Error(t, err, "RemoteStorage.GetDynamicSecretLease must fail for a lease ID that does not exist")
}

// --- ListDynamicSecretConfigs ---

func TestConformance_ListDynamicSecretConfigs(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-ldsc-other-project", "", []string{"dev"})
	require.NoError(t, err)
	otherEnvs, err := h.ls.ListEnvironmentsByProject(ctx, otherProject.ID)
	require.NoError(t, err)
	require.NotEmpty(t, otherEnvs)

	newConfig := func(projectID, environmentID uint, name string) *models.DynamicSecretConfig {
		cfg, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
			Name: name, ProjectID: projectID, EnvironmentID: environmentID, BackendType: "postgres",
			CreationTemplate: "-- noop", DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400, MaxActiveLeases: 5,
			CreatedBy: "conformance-test",
		})
		require.NoError(t, err)
		return cfg
	}

	target := newConfig(h.projectID, h.environmentID, "conformance-ldsc-target")
	// A config in a DIFFERENT project must not appear when filtering by
	// h.projectID -- the scope-drop risk this method exists to guard against.
	_ = newConfig(otherProject.ID, otherEnvs[0].ID, "conformance-ldsc-other")

	localList, err := h.ls.ListDynamicSecretConfigs(ctx, h.projectID, h.environmentID)
	require.NoError(t, err)
	remoteList, err := h.rs.ListDynamicSecretConfigs(ctx, h.projectID, h.environmentID)
	require.NoError(t, err, "RemoteStorage.ListDynamicSecretConfigs must succeed for the caller's own project")

	require.Len(t, localList, 1, "sanity: LocalStorage must return only the target project's config")
	require.Len(t, remoteList, 1,
		"RemoteStorage.ListDynamicSecretConfigs must return only the config genuinely scoped to the "+
			"caller-supplied project -- a dropped/ignored project_id on the wire would leak the other "+
			"project's config too")
	assertFieldExhaustiveEqual(t, "ListDynamicSecretConfigs[0] (RemoteStorage vs LocalStorage)",
		localList[0], remoteList[0], map[string]bool{})
	assert.Equal(t, target.ID, remoteList[0].ID)
}

// --- ListDynamicSecretLeases ---

func TestConformance_ListDynamicSecretLeases(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newConfig := func(name string) *models.DynamicSecretConfig {
		cfg, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
			Name: name, ProjectID: h.projectID, EnvironmentID: h.environmentID, BackendType: "postgres",
			CreationTemplate: "-- noop", DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400, MaxActiveLeases: 5,
			CreatedBy: "conformance-test",
		})
		require.NoError(t, err)
		return cfg
	}
	newLease := func(configID uint, leaseID string) *models.DynamicSecretLease {
		l, err := h.ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
			ConfigID: configID, LeaseID: leaseID, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			RoleName: "conformance-role-" + leaseID, Status: "active",
			IssuedAt: time.Now().UTC().Truncate(time.Second), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		})
		require.NoError(t, err)
		return l
	}

	targetConfig := newConfig("conformance-ldsl-target-config")
	otherConfig := newConfig("conformance-ldsl-other-config")
	targetLease := newLease(targetConfig.ID, "conformance-ldsl-target-lease")
	// A lease belonging to a DIFFERENT config must not appear -- the scope-drop
	// risk this method exists to guard against.
	_ = newLease(otherConfig.ID, "conformance-ldsl-other-lease")

	localList, err := h.ls.ListDynamicSecretLeases(ctx, targetConfig.ID)
	require.NoError(t, err)
	remoteList, err := h.rs.ListDynamicSecretLeases(ctx, targetConfig.ID)
	require.NoError(t, err, "RemoteStorage.ListDynamicSecretLeases must succeed for a config that genuinely exists")

	require.Len(t, localList, 1, "sanity: LocalStorage must return only the target config's lease")
	require.Len(t, remoteList, 1,
		"RemoteStorage.ListDynamicSecretLeases must return only the lease genuinely scoped to the "+
			"caller-supplied config -- a dropped/ignored config_id on the wire would leak the other "+
			"config's lease too")
	assertFieldExhaustiveEqual(t, "ListDynamicSecretLeases[0] (RemoteStorage vs LocalStorage)",
		localList[0], remoteList[0], map[string]bool{})
	assert.Equal(t, targetLease.ID, remoteList[0].ID)
}

// --- CountActiveLeases ---

func TestConformance_CountActiveLeases(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newConfig := func(name string) *models.DynamicSecretConfig {
		cfg, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
			Name: name, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			BackendType: "postgres", CreationTemplate: "-- noop", DefaultTTLSeconds: 3600,
			MaxTTLSeconds: 86400, MaxActiveLeases: 10, CreatedBy: "conformance-test",
		})
		require.NoError(t, err)
		return cfg
	}

	// Negative case (brief's suggested example): a config with zero leases must
	// count zero on both facades. A SEPARATE, never-queried-before config is
	// used for this (rather than re-querying the populated config below) --
	// RemoteStorage.HTTPClient caches a GET response for 5 minutes keyed by its
	// exact URL (client.go's Get, the same mechanism LockUserForUpdate's class-6
	// conformance test exercises deliberately); querying the SAME config_id
	// twice before/after seeding leases would silently replay the first (zero)
	// response instead of genuinely re-querying, certifying nothing.
	zeroCfg := newConfig("conformance-cal-zero-config")
	localZero, err := h.ls.CountActiveLeases(ctx, zeroCfg.ID)
	require.NoError(t, err)
	remoteZero, err := h.rs.CountActiveLeases(ctx, zeroCfg.ID)
	require.NoError(t, err, "RemoteStorage.CountActiveLeases must succeed for a config that genuinely exists")
	assert.Equal(t, int64(0), localZero, "sanity: a config with zero leases must count zero")
	assert.Equal(t, int64(0), remoteZero, "RemoteStorage.CountActiveLeases must also count zero for a config with zero leases")

	populatedCfg := newConfig("conformance-cal-populated-config")
	newLease := func(leaseID, status string) {
		_, err := h.ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
			ConfigID: populatedCfg.ID, LeaseID: leaseID, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			RoleName: "conformance-role-" + leaseID, Status: status,
			IssuedAt: time.Now().UTC().Truncate(time.Second), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		})
		require.NoError(t, err)
	}
	// local_dynamic.go's own #411 doc: "active" AND "revoke_failed" both still
	// hold a live credential upstream and must count; "revoked" and "expired" do
	// not -- exercising the exclusion side of the filter is the point, not just
	// the inclusion side (an over-broad filter would silently inflate this count
	// and let a caller exceed MaxActiveLeases; an over-narrow one would let a
	// revoke_failed lease's still-live credential go uncounted forever).
	newLease("conformance-cal-active", "active")
	newLease("conformance-cal-revoke-failed", "revoke_failed")
	newLease("conformance-cal-revoked", "revoked")
	newLease("conformance-cal-expired", "expired")

	localCount, err := h.ls.CountActiveLeases(ctx, populatedCfg.ID)
	require.NoError(t, err)
	remoteCount, err := h.rs.CountActiveLeases(ctx, populatedCfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), localCount, "sanity: only active + revoke_failed leases count")
	assert.Equal(t, int64(2), remoteCount,
		"RemoteStorage.CountActiveLeases must count exactly the still-live leases (active + revoke_failed), "+
			"matching LocalStorage against the same backing store -- a widened or narrowed status filter on "+
			"the wire would over- or under-count")
}

// --- CountDynamicSecretConfigsByClassification ---

func TestConformance_CountDynamicSecretConfigsByClassification(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newConfig := func(name, classification string) {
		_, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
			Name: name, ProjectID: h.projectID, EnvironmentID: h.environmentID, BackendType: "postgres",
			CreationTemplate: "-- noop", DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400, MaxActiveLeases: 5,
			Classification: classification, CreatedBy: "conformance-test",
		})
		require.NoError(t, err)
	}
	newConfig("conformance-cdscbc-confidential-1", "confidential")
	newConfig("conformance-cdscbc-confidential-2", "confidential")
	newConfig("conformance-cdscbc-internal", "internal")
	newConfig("conformance-cdscbc-unclassified", "")

	// Install-wide (no project scope): LocalStorage and RemoteStorage are
	// necessarily reading the identical aggregate over the SAME rows here, so
	// there is no local-scenario/remote-scenario split to make -- just a direct
	// same-store comparison, like GetSecretByName.
	localCounts, err := h.ls.CountDynamicSecretConfigsByClassification(ctx)
	require.NoError(t, err)
	remoteCounts, err := h.rs.CountDynamicSecretConfigsByClassification(ctx)
	require.NoError(t, err, "RemoteStorage.CountDynamicSecretConfigsByClassification must succeed")

	assert.Equal(t, 2, localCounts["confidential"], "sanity: two confidential configs seeded")
	assert.Equal(t, 1, localCounts["internal"], "sanity: one internal config seeded")
	assert.Equal(t, 1, localCounts[""], "sanity: one unclassified config seeded")
	assert.Equal(t, localCounts, remoteCounts,
		"RemoteStorage.CountDynamicSecretConfigsByClassification must return the identical per-classification "+
			"counts as LocalStorage against the same backing store")
}

// --- ListExpiredActiveLeases ---

func TestConformance_ListExpiredActiveLeases(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	cfg, err := h.ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "conformance-leal-config", ProjectID: h.projectID, EnvironmentID: h.environmentID,
		BackendType: "postgres", CreationTemplate: "-- noop", DefaultTTLSeconds: 3600,
		MaxTTLSeconds: 86400, MaxActiveLeases: 10, CreatedBy: "conformance-test",
	})
	require.NoError(t, err)

	cutoff := time.Now().UTC()
	past := cutoff.Add(-1 * time.Hour)
	future := cutoff.Add(1 * time.Hour)

	newLease := func(leaseID, status string, expiresAt time.Time) {
		_, err := h.ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
			ConfigID: cfg.ID, LeaseID: leaseID, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			RoleName: "conformance-role-" + leaseID, Status: status,
			IssuedAt: past.Add(-time.Hour), ExpiresAt: expiresAt,
		})
		require.NoError(t, err)
	}

	// Must be INCLUDED: past expiry, still-live status.
	newLease("conformance-leal-active-expired", "active", past)
	newLease("conformance-leal-revokefailed-expired", "revoke_failed", past)
	// Must be EXCLUDED: past expiry but already revoked -- no live credential
	// left to drop, so re-including it would make the sweep re-attempt a revoke
	// against a credential that's already gone.
	newLease("conformance-leal-revoked-expired", "revoked", past)
	// Must be EXCLUDED -- the brief's explicit off-by-scope risk: a genuinely
	// still-live, still-active lease that has NOT expired yet must not be swept.
	newLease("conformance-leal-active-future", "active", future)

	localList, err := h.ls.ListExpiredActiveLeases(ctx, cutoff)
	require.NoError(t, err)
	remoteList, err := h.rs.ListExpiredActiveLeases(ctx, cutoff)
	require.NoError(t, err, "RemoteStorage.ListExpiredActiveLeases must succeed")

	idsOf := func(leases []*models.DynamicSecretLease) []string {
		ids := make([]string, len(leases))
		for i, l := range leases {
			ids[i] = l.LeaseID
		}
		return ids
	}
	wantIDs := []string{"conformance-leal-active-expired", "conformance-leal-revokefailed-expired"}
	assert.ElementsMatch(t, wantIDs, idsOf(localList),
		"sanity: LocalStorage must return exactly the two still-live, past-expiry leases")
	assert.ElementsMatch(t, wantIDs, idsOf(remoteList),
		"RemoteStorage.ListExpiredActiveLeases must return exactly the two still-live, past-expiry leases -- "+
			"neither a not-yet-expired lease nor an already-revoked one, matching LocalStorage against the "+
			"same backing store (a widened/narrowed status or expiry filter on the wire would leak or drop rows)")
}

// --- GetRotationPolicy ---

func TestConformance_GetRotationPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	policy := &models.RotationPolicy{
		Name: "conformance-grp-policy", Description: "conformance test policy", Scope: "project",
		ProjectID: uintPtr(h.projectID), IntervalDays: 30, AlertDaysBefore: 7, NotifyOnBreach: true,
		IsActive: true, RotationState: "idle", CreatedBy: "conformance-test",
	}
	require.NoError(t, h.ls.CreateRotationPolicy(ctx, policy))

	// Same row, two facades -- no server-side business logic runs on a plain
	// Get, so a clean field-exhaustive comparison, same reasoning as
	// GetSecretByName.
	localOut, err := h.ls.GetRotationPolicy(ctx, policy.ID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetRotationPolicy(ctx, policy.ID)
	require.NoError(t, err, "RemoteStorage.GetRotationPolicy must succeed for a policy that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetRotationPolicy (RemoteStorage vs LocalStorage, same row)",
		localOut, remoteOut, map[string]bool{})

	_, err = h.rs.GetRotationPolicy(ctx, policy.ID+987654)
	assert.Error(t, err, "RemoteStorage.GetRotationPolicy must fail for a policy that does not exist")
}

// --- ListRotationPolicies ---

func TestConformance_ListRotationPolicies(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lrp-other-project", "", []string{"dev"})
	require.NoError(t, err)

	newPolicy := func(projectID uint, name string) *models.RotationPolicy {
		p := &models.RotationPolicy{
			Name: name, Scope: "project", ProjectID: uintPtr(projectID), IntervalDays: 30,
			AlertDaysBefore: 7, NotifyOnBreach: true, IsActive: true, RotationState: "idle",
			CreatedBy: "conformance-test",
		}
		require.NoError(t, h.ls.CreateRotationPolicy(ctx, p))
		return p
	}

	target := newPolicy(h.projectID, "conformance-lrp-target")
	// A policy scoped to a DIFFERENT project must not appear -- the scope-drop
	// risk this method exists to guard against.
	_ = newPolicy(otherProject.ID, "conformance-lrp-other")

	localList, err := h.ls.ListRotationPolicies(ctx, uintPtr(h.projectID), nil)
	require.NoError(t, err)
	remoteList, err := h.rs.ListRotationPolicies(ctx, uintPtr(h.projectID), nil)
	require.NoError(t, err, "RemoteStorage.ListRotationPolicies must succeed for the caller's own project")

	require.Len(t, localList, 1, "sanity: LocalStorage must return only the target project's policy")
	require.Len(t, remoteList, 1,
		"RemoteStorage.ListRotationPolicies must return only the policy genuinely scoped to the "+
			"caller-supplied project -- a dropped/ignored project_id on the wire would leak the other "+
			"project's policy too")
	assertFieldExhaustiveEqual(t, "ListRotationPolicies[0] (RemoteStorage vs LocalStorage)",
		localList[0], remoteList[0], map[string]bool{})
	assert.Equal(t, target.ID, remoteList[0].ID)
}

// --- CreateRotationPolicy, UpdateRotationPolicy: SKIPPED ---
//
// See this file's package doc above for the confirmed wire-format bug that
// makes both methods fail unconditionally over RemoteStorage (every real
// attempt during this tranche's own development failed with the server's
// 400 "interval_days must be at least 1", for callers that set IntervalDays
// to a valid value) -- not a fixture-cost skip, a discovered defect that
// needs a fix to remote_rotation_policies.go/rotation_policies_handler.go
// before a real conformance test can be written for either method.

// --- DeleteRotationPolicy ---

func TestConformance_DeleteRotationPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newPolicy := func(suffix string) *models.RotationPolicy {
		p := &models.RotationPolicy{
			Name: "conformance-drp-" + suffix, Scope: "project", ProjectID: uintPtr(h.projectID),
			IntervalDays: 30, AlertDaysBefore: 7, NotifyOnBreach: true, IsActive: true,
			RotationState: "idle", CreatedBy: "conformance-test",
		}
		require.NoError(t, h.ls.CreateRotationPolicy(ctx, p))
		return p
	}

	localPolicy := newPolicy("local")
	require.NoError(t, h.ls.DeleteRotationPolicy(ctx, localPolicy.ID))

	remotePolicy := newPolicy("remote")
	require.NoError(t, h.rs.DeleteRotationPolicy(ctx, remotePolicy.ID),
		"RemoteStorage.DeleteRotationPolicy must succeed for a policy that genuinely exists")

	_, localErr := h.ls.GetRotationPolicy(ctx, localPolicy.ID)
	_, remoteErr := h.ls.GetRotationPolicy(ctx, remotePolicy.ID)
	assert.Error(t, localErr, "sanity: the local policy must no longer be retrievable")
	assert.Error(t, remoteErr,
		"the policy deleted via RemoteStorage must actually be gone server-side, not just report success")

	// Deleting an already-deleted policy: the RAW LocalStorage primitive is an
	// idempotent no-op (GORM's default soft-delete scope excludes the
	// already-deleted row from the second DELETE's WHERE clause, so
	// RowsAffected=0 with no error) -- but RemoteStorage's proxy runs
	// core.DeleteRotationPolicy, which re-fetches the policy via
	// GetRotationPolicy FIRST (to build the audit-log message) and that fetch
	// now 404s, surfacing as a genuine error through the wire. This asymmetry
	// is a real, pre-existing core-vs-raw-storage semantic difference (not a
	// proxy-layer wire bug): the raw primitive was always silently idempotent;
	// the core layer was always fetch-first. Both are asserted here so a future
	// regression in either direction is caught.
	assert.NoError(t, h.ls.DeleteRotationPolicy(ctx, localPolicy.ID),
		"sanity: LocalStorage's raw DeleteRotationPolicy primitive is an idempotent no-op on an already-deleted row")
	assert.Error(t, h.rs.DeleteRotationPolicy(ctx, remotePolicy.ID),
		"RemoteStorage.DeleteRotationPolicy must fail for an already-deleted policy -- core.DeleteRotationPolicy "+
			"re-fetches the row first and that fetch now 404s, not silently no-op a second time")
}
