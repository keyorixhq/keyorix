package store

// full_row_writer_interleave_test.go — TEST-GUARDS-NOV-1 item 1.
//
// docs/full-row-write-exempt.tsv still lists eight full-row writers (Save, or
// Select("*").Updates) of security-state rows. Each is exempt because a conditional WHERE
// (state, decision, revoked/approved flags) is argued to stop a stale struct from
// reverting a concurrent narrow write. These tests turn that argument into an
// assertion, per writer, at the storage layer, on SQLite and on Postgres:
//
//	replica A reads the row            (the struct the operation will later write)
//	replica B commits a narrow write   (revoke, reject, close, lift, delete the secret ...)
//	replica A writes its stale struct
//	-> the narrow write must still be there afterwards.
//
// Replicas are two independent LocalStorage values over two separate connections into
// ONE database (a file for SQLite, one schema for Postgres), the shape the repo's
// cross-replica tests use. The order is forced by running the steps sequentially, the way
// full_row_write_repro_test.go does, so every case is deterministic.
//
// Style note: the user-row version of this (FIX-USER-ROW-NARROW-1, #4138) lives in
// internal/core (cta_review_user_row_narrow_*_test.go) because UpdateUser's fix is in
// core; these eight writers are store primitives, so the interleaving is driven here.
//
// What this does NOT cover: the core callers' own locks (they only add safety), writers
// that are not on the exempt list, and the reverse order for writers with no second
// writer (a transition has nothing narrower to lose). Findings: see
// TestUpdateLegalHold_StaleUnreleasedSave_KnownOpen below.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// interleaveEnv is two replicas over one database.
type interleaveEnv struct {
	a, b *LocalStorage
	db   *gorm.DB // third handle, for seeding and for reading the final row
}

// interleaveBackends names the backends; postgres skips without KEYORIX_TEST_PG_DSN.
var interleaveBackends = []string{"sqlite", "postgres"}

func newInterleaveEnv(t *testing.T, backend string) *interleaveEnv {
	t.Helper()
	var open func() *gorm.DB
	switch backend {
	case "sqlite":
		dsn := "file:" + filepath.Join(t.TempDir(), "i.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
		open = func() *gorm.DB {
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
			require.NoError(t, err)
			t.Cleanup(func() {
				if sqlDB, e := db.DB(); e == nil {
					_ = sqlDB.Close()
				}
			})
			return db
		}
	case "postgres":
		dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
		open = func() *gorm.DB { return pgOpen(t, dsn) }
	default:
		t.Fatalf("unknown backend %q", backend)
	}
	seed := open()
	require.NoError(t, seed.AutoMigrate(
		&models.MachineIdentity{}, &models.ProjectMembership{}, &models.ProjectInvitation{},
		&models.AccessRequest{}, &models.SecretNode{}, &models.AccessReviewCampaign{},
		&models.AccessReviewItem{}, &models.LegalHold{}, &models.RiskException{},
	))
	return &interleaveEnv{a: NewLocalStorage(open()), b: NewLocalStorage(open()), db: seed}
}

func interleaveNow() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }

// forEachInterleaveBackend runs fn once per backend as a subtest.
func forEachInterleaveBackend(t *testing.T, fn func(t *testing.T, env *interleaveEnv)) {
	t.Helper()
	for _, backend := range interleaveBackends {
		t.Run(backend, func(t *testing.T) { fn(t, newInterleaveEnv(t, backend)) })
	}
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_TransitionMachineIdentityState(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		seed := &models.MachineIdentity{ProjectID: 1, Name: "ci", State: "active", CreatedAt: interleaveNow(), UpdatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		stale, err := env.a.GetMachineIdentity(ctx, seed.ID) // A: classify/suspend reads it active
		require.NoError(t, err)

		// B: revoke commits.
		fresh, err := env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		revokedAt := interleaveNow().Add(time.Minute)
		fresh.State, fresh.RevokedAt, fresh.UpdatedAt = "revoked", &revokedAt, revokedAt
		ok, err := env.b.TransitionMachineIdentityState(ctx, fresh, "active")
		require.NoError(t, err)
		require.True(t, ok)

		// A: a classify (same state, new label) and a suspend, both from the stale read.
		stale.Classification = "restricted"
		ok, err = env.a.TransitionMachineIdentityState(ctx, stale, "active")
		require.NoError(t, err)
		assert.False(t, ok, "a classify built on a pre-revoke read must lose the state CAS")
		stale.Classification, stale.State = "", "suspended"
		ok, err = env.a.TransitionMachineIdentityState(ctx, stale, "active")
		require.NoError(t, err)
		assert.False(t, ok, "a suspend built on a pre-revoke read must lose the state CAS (revoked is terminal)")

		got, err := env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		assert.Equal(t, "revoked", got.State, "the revoke was reverted by a stale full-row write")
		require.NotNil(t, got.RevokedAt, "revoked_at was cleared by a stale full-row write")
		assert.Empty(t, got.Classification, "the losing classify must not leave any column behind")
	})
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_TransitionProjectMembershipState(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		seed := &models.ProjectMembership{ProjectID: 1, UserID: 7, Role: "viewer", State: "provisioned", InvitedAt: interleaveNow(), UpdatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.ProjectMembership // A: an activate reads it provisioned
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		var fresh models.ProjectMembership // B: a revoke commits
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		revokedAt := interleaveNow().Add(time.Minute)
		fresh.State, fresh.RevokedAt, fresh.UpdatedAt = "revoked", &revokedAt, revokedAt
		ok, err := env.b.TransitionProjectMembershipState(ctx, &fresh, "provisioned")
		require.NoError(t, err)
		require.True(t, ok)

		activatedAt := interleaveNow().Add(2 * time.Minute)
		stale.State, stale.ActivatedAt, stale.UpdatedAt = "active", &activatedAt, activatedAt
		ok, err = env.a.TransitionProjectMembershipState(ctx, &stale, "provisioned")
		require.NoError(t, err)
		assert.False(t, ok, "an activate built on a pre-revoke read must lose the state CAS")

		var got models.ProjectMembership
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.Equal(t, "revoked", got.State, "the revoke was reverted by a stale activate")
		assert.NotNil(t, got.RevokedAt)
		assert.Nil(t, got.ActivatedAt, "a losing activate must not leave activated_at behind")
	})
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_UpdateProjectInvitation(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		exp := interleaveNow().Add(24 * time.Hour)
		seed := &models.ProjectInvitation{ProjectID: 1, Email: "new@example.com", Role: "viewer", State: "pending", ExpiresAt: &exp, CreatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.ProjectInvitation // A: an accept reads it pending
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		var fresh models.ProjectInvitation // B: a revoke commits
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		revokedAt := interleaveNow().Add(time.Minute)
		fresh.State, fresh.RevokedAt = "revoked", &revokedAt
		ok, err := env.b.UpdateProjectInvitation(ctx, &fresh)
		require.NoError(t, err)
		require.True(t, ok)

		acceptedAt := interleaveNow().Add(2 * time.Minute)
		stale.State, stale.AcceptedAt = "accepted", &acceptedAt
		ok, err = env.a.UpdateProjectInvitation(ctx, &stale)
		require.NoError(t, err)
		assert.False(t, ok, "an accept built on a pre-revoke read must lose the pending CAS")

		var got models.ProjectInvitation
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.Equal(t, "revoked", got.State, "the revoke was reverted by a stale accept")
		assert.NotNil(t, got.RevokedAt)
		assert.Nil(t, got.AcceptedAt)
	})
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_UpdateAccessRequest(t *testing.T) {
	t.Run("reject_beats_stale_approve", func(t *testing.T) {
		forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
			ctx := context.Background()
			seed := &models.AccessRequest{ProjectID: 1, UserID: 7, SuggestedRole: "viewer", State: "pending", CreatedAt: interleaveNow()}
			require.NoError(t, env.db.Create(seed).Error)

			var stale models.AccessRequest // A: an approve reads it pending
			require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

			var fresh models.AccessRequest // B: a reject commits
			require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
			resolvedAt := interleaveNow().Add(time.Minute)
			fresh.State, fresh.ResolvedBy, fresh.ResolvedAt = "rejected", 9, &resolvedAt
			ok, err := env.b.UpdateAccessRequest(ctx, &fresh)
			require.NoError(t, err)
			require.True(t, ok)

			stale.State, stale.GrantedRole, stale.ResolvedBy = "approved", "admin", 1
			ok, err = env.a.UpdateAccessRequest(ctx, &stale)
			require.NoError(t, err)
			assert.False(t, ok, "an approve built on a pre-reject read must lose the pending CAS")

			var got models.AccessRequest
			require.NoError(t, env.db.First(&got, seed.ID).Error)
			assert.Equal(t, "rejected", got.State, "the reject was reverted by a stale approve")
			assert.Equal(t, uint(9), got.ResolvedBy)
			assert.Empty(t, got.GrantedRole, "a losing approve must not leave a granted role behind")
		})
	})

	// The secret-scoped approve re-checks the secret inside the same transaction as the
	// CAS: a secret deleted between the approver's read and the write must not leave an
	// approved request that a later restore would revive.
	t.Run("secret_delete_beats_stale_approve", func(t *testing.T) {
		forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
			ctx := context.Background()
			secret := &models.SecretNode{Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}
			require.NoError(t, env.db.Create(secret).Error)
			seed := &models.AccessRequest{ProjectID: 1, UserID: 7, SecretID: &secret.ID, State: "pending", CreatedAt: interleaveNow()}
			require.NoError(t, env.db.Create(seed).Error)

			var stale models.AccessRequest // A: an approve reads the request pending
			require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

			require.NoError(t, env.b.db.Delete(&models.SecretNode{}, secret.ID).Error) // B: the secret is deleted

			resolvedAt := interleaveNow().Add(time.Minute)
			stale.State, stale.ResolvedBy, stale.ResolvedAt = "approved", 1, &resolvedAt
			ok, err := env.a.UpdateAccessRequest(ctx, &stale)
			assert.Error(t, err, "approving a request for a deleted secret must be refused")
			assert.False(t, ok)

			var got models.AccessRequest
			require.NoError(t, env.db.First(&got, seed.ID).Error)
			assert.Equal(t, "pending", got.State, "the refused approve left an approved request for a deleted secret behind")
		})
	})
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_UpdateAccessReviewCampaign(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		seed := &models.AccessReviewCampaign{ProjectID: 1, Name: "Q4", State: "open", CreatedBy: 1, CreatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.AccessReviewCampaign // A: a normal close reads it open
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		var fresh models.AccessReviewCampaign // B: a FORCED close commits (items still pending)
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		closedAt := interleaveNow().Add(time.Minute)
		fresh.State, fresh.ClosedBy, fresh.ClosedAt, fresh.ForcedIncomplete = "closed", 9, &closedAt, true
		ok, err := env.b.UpdateAccessReviewCampaign(ctx, &fresh)
		require.NoError(t, err)
		require.True(t, ok)

		later := interleaveNow().Add(2 * time.Minute)
		stale.State, stale.ClosedBy, stale.ClosedAt = "closed", 1, &later
		ok, err = env.a.UpdateAccessReviewCampaign(ctx, &stale)
		require.NoError(t, err)
		assert.False(t, ok, "a close built on a pre-close read must lose the open CAS")

		var got models.AccessReviewCampaign
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.True(t, got.ForcedIncomplete, "the forced-incomplete mark was erased by a stale close: the campaign would pass as a genuine recertification")
		assert.Equal(t, uint(9), got.ClosedBy)
	})
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_UpdateAccessReviewItem(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		campaign := &models.AccessReviewCampaign{ProjectID: 1, Name: "Q4", State: "open", CreatedBy: 1, CreatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(campaign).Error)
		seed := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: 7, Source: "role", Decision: "pending"}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.AccessReviewItem // A: reviewer 1 reads it pending, will attest
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		var fresh models.AccessReviewItem // B: reviewer 9 revokes the access
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		decidedAt := interleaveNow().Add(time.Minute)
		fresh.Decision, fresh.DecidedBy, fresh.DecidedAt = "revoked", 9, &decidedAt
		ok, err := env.b.UpdateAccessReviewItem(ctx, &fresh)
		require.NoError(t, err)
		require.True(t, ok)

		stale.Decision, stale.DecidedBy = "attested", 1
		ok, err = env.a.UpdateAccessReviewItem(ctx, &stale)
		require.NoError(t, err)
		assert.False(t, ok, "an attest built on a pre-revoke read must lose the pending CAS")

		var got models.AccessReviewItem
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.Equal(t, "revoked", got.Decision, "the revoke decision was overwritten by a stale attest")
		assert.Equal(t, uint(9), got.DecidedBy)
	})
}

func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_ApproveRiskExceptionIfPending(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		seed := &models.RiskException{Title: "sod", Category: "sod", CreatedBy: 1, CreatedAt: interleaveNow(), ExpiresAt: interleaveNow().Add(24 * time.Hour)}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.RiskException // A: an approve reads it pending
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		var fresh models.RiskException // B: a revoke commits
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		revokedAt := interleaveNow().Add(time.Minute)
		fresh.Revoked, fresh.RevokedBy, fresh.RevokedAt = true, 9, &revokedAt
		ok, err := env.b.RevokeRiskExceptionIfNotRevoked(ctx, &fresh)
		require.NoError(t, err)
		require.True(t, ok)

		approvedAt := interleaveNow().Add(2 * time.Minute)
		stale.Approved, stale.ApprovedBy, stale.ApprovedAt = true, 2, &approvedAt
		ok, err = env.a.ApproveRiskExceptionIfPending(ctx, &stale)
		require.NoError(t, err)
		assert.False(t, ok, "an approve built on a pre-revoke read must lose the two-flag CAS")

		var got models.RiskException
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.True(t, got.Revoked, "the revoke was reverted by a stale approve: a withdrawn exception is live again")
		assert.False(t, got.Approved, "a losing approve must not leave approved=true behind")
	})
}

// UpdateLegalHold is a plain Save (upsert). Its one caller, LiftLegalHold, always writes
// released=true, so a stale lift cannot re-activate a hold and cannot touch another hold.
func TestFullRowWriters_NarrowWriteSurvivesStaleTransition_UpdateLegalHold(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		seed := &models.LegalHold{Reason: "case 1", PlacedBy: 1, PlacedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.LegalHold // A: a lift reads hold 1 active
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		// B: lifts hold 1, then places hold 2.
		var fresh models.LegalHold
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		releasedAt := interleaveNow().Add(time.Minute)
		fresh.Released, fresh.ReleasedBy, fresh.ReleasedAt, fresh.ReleaseReason = true, 9, &releasedAt, "B lifts"
		require.NoError(t, env.b.UpdateLegalHold(ctx, &fresh))
		second, err := env.b.CreateLegalHold(ctx, &models.LegalHold{Reason: "case 2", PlacedBy: 9, PlacedAt: interleaveNow().Add(2 * time.Minute)})
		require.NoError(t, err)

		// A: its lift (released=true, as LiftLegalHold always writes) lands last.
		lateAt := interleaveNow().Add(3 * time.Minute)
		stale.Released, stale.ReleasedBy, stale.ReleasedAt, stale.ReleaseReason = true, 1, &lateAt, "A lifts"
		require.NoError(t, env.a.UpdateLegalHold(ctx, &stale))

		var got models.LegalHold
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.True(t, got.Released, "hold 1 must stay lifted")
		active, err := env.b.GetActiveLegalHold(ctx)
		require.NoError(t, err)
		require.NotNil(t, active, "hold 2, placed by B in between, was dropped by A's stale write")
		assert.Equal(t, second.ID, active.ID)
		assert.False(t, active.Released)
		// Known residual (full-row-write-exempt.tsv, RESIDUAL): the second lift overwrites
		// released_by / release_reason. Logged, not asserted: it is by-design noise.
		t.Logf("residual: released_by=%d release_reason=%q (B wrote 9/%q)", got.ReleasedBy, got.ReleaseReason, "B lifts")
	})
}

// TestUpdateLegalHold_StaleUnreleasedSave_KnownOpen is the one red interleaving found by
// this file, kept green as a known-open pin. The primitive is a full-row Save with no
// conditional WHERE: if a caller hands it a struct read BEFORE another replica lifted the
// hold, and that struct still says released=false, the lift is reverted and the hold is
// active again (the reverse also holds: a stale released=true struct would lift a hold a
// concurrent writer had re-opened by row edit).
//
// Reachability (CLAUDE.md: a storage-layer demonstration is not application-level
// reachability): none today. LiftLegalHold, the only caller, always sets released=true
// before the write, so no production path hands the primitive an unreleased stale struct.
// The class is latent: any new caller that edits a hold in place and saves it would
// silently re-activate or drop a hold.
//
// Proposed fix (not applied: this PR is tests only): replace Save with a conditional,
// column-scoped lift, `UPDATE legal_holds SET released=true, released_by=?, released_at=?,
// release_reason=? WHERE id=? AND released=false`, returning whether a row matched. That
// also removes the double-lift residual (second lifter gets matched=false).
//
// This test asserts the CURRENT (unsafe) behaviour. When the primitive is fixed it fails
// on purpose: convert it into the positive assertion (the lift survives) and delete the
// _KnownOpen suffix, as TestKnownOpenTolerances_AreLoadBearing does for its entries.
func TestUpdateLegalHold_StaleUnreleasedSave_KnownOpen(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		seed := &models.LegalHold{Reason: "case 1", PlacedBy: 1, PlacedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.LegalHold
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		var fresh models.LegalHold
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		releasedAt := interleaveNow().Add(time.Minute)
		fresh.Released, fresh.ReleasedBy, fresh.ReleasedAt = true, 9, &releasedAt
		require.NoError(t, env.b.UpdateLegalHold(ctx, &fresh))

		stale.Reason = "case 1 (edited)" // a hypothetical in-place edit by A, still released=false
		require.NoError(t, env.a.UpdateLegalHold(ctx, &stale))

		var got models.LegalHold
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		if got.Released {
			t.Fatalf("UpdateLegalHold now keeps a concurrent lift (released=true survived a stale released=false Save): " +
				"the known-open finding is fixed. Turn this test into the positive assertion and drop the _KnownOpen suffix.")
		}
		t.Logf("known open (latent, no production caller): stale released=false Save reverted another replica's lift")
	})
}
