package admin

// Tests for collectBreakGlassReviewPosture (the two findings Andrei decided on
// #2461) and the tls_mode informational line in collectTLSPosture. The
// break-glass tests run on SQLite always and on PostgreSQL when
// KEYORIX_TEST_PG_DSN is set (pgAdminTestDSN skips otherwise).

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// breakGlassPostureBackends runs fn once per backend with a config pointing at
// a fresh, empty database. break_glass is enabled with the default 72h window.
func breakGlassPostureBackends(t *testing.T, fn func(t *testing.T, cfg *config.Config)) {
	t.Helper()
	newCfg := func(t *testing.T) *config.Config {
		cfg := &config.Config{}
		cfg.BreakGlass.Enabled = true
		require.NoError(t, i18n.InitializeForTesting())
		return cfg
	}
	t.Run("sqlite", func(t *testing.T) {
		cfg := newCfg(t)
		cfg.Storage.Type = "local"
		cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "posture.db")
		fn(t, cfg)
	})
	t.Run("postgres", func(t *testing.T) {
		base := pgAdminTestDSN(t)
		cfg := newCfg(t)
		cfg.Storage.Type = "postgres"
		cfg.Storage.Database.DSN = pgdsn.IsolatedDatabase(t, base, "posture_bg")
		fn(t, cfg)
	})
}

// seedAdmin creates an active user holding the install's admin role (creating
// the role on first use) and returns the user.
func seedAdmin(ctx context.Context, t *testing.T, store corestorage.Storage, name string) *models.User {
	t.Helper()
	user, err := store.CreateUser(ctx, &models.User{
		Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io",
		IsActive: true, AccountState: core.AccountActive,
	})
	require.NoError(t, err)
	roleName, err := identity.NewFoldedName("admin")
	require.NoError(t, err)
	role, err := store.GetRoleByName(ctx, roleName.Folded())
	if err != nil || role == nil {
		role, err = store.CreateRole(ctx, roleName, "install administrator")
		require.NoError(t, err)
		// What makes a role admin-tier is the ADR-084 flag, not its name
		// (ListGlobalAdminHolders resolves holders through it).
		require.NoError(t, store.SetRoleBypassesPermissionChecks(ctx, role.ID, true))
	}
	require.NoError(t, store.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{}))
	return user
}

// seedActivation stores one (expired-state, so the one-active-per-project+user
// index never applies) activation created `age` ago, reviewed or not.
func seedActivation(ctx context.Context, t *testing.T, store corestorage.Storage, userID, projectID uint, age time.Duration, reviewed bool) uint {
	t.Helper()
	created := time.Now().Add(-age)
	a := &models.BreakGlassActivation{
		ProjectID: projectID, UserID: userID, RoleName: "project_developer",
		Justification: "SECRET-JUSTIFICATION-MUST-NOT-APPEAR", State: "expired", CreatedAt: created,
	}
	if reviewed {
		at := created.Add(time.Hour)
		a.ReviewedBy, a.ReviewedAt = userID+1000, &at
	}
	got, err := store.CreateBreakGlassActivation(ctx, a)
	require.NoError(t, err)
	return got.ID
}

func breakGlassFindings(r *postureReport) []postureDeviation {
	var out []postureDeviation
	for _, d := range r.deviations {
		if d.category == "break-glass-review" {
			out = append(out, d)
		}
	}
	return out
}

func TestCollectBreakGlassReviewPosture_UnreviewedPastWindow(t *testing.T) {
	breakGlassPostureBackends(t, func(t *testing.T, cfg *config.Config) {
		err := withUsableStorage(cfg, func(store corestorage.Storage) error {
			ctx := context.Background()
			// Two admins, so only the review-window finding can fire.
			a1 := seedAdmin(ctx, t, store, "alice")
			seedAdmin(ctx, t, store, "bob")

			stale := seedActivation(ctx, t, store, a1.ID, 7, 100*time.Hour, false)
			seedActivation(ctx, t, store, a1.ID, 8, time.Hour, false)    // inside the window
			seedActivation(ctx, t, store, a1.ID, 9, 100*time.Hour, true) // reviewed

			report := &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, core.NewKeyorixCore(store), report)

			findings := breakGlassFindings(report)
			require.Len(t, findings, 1, "only the stale unreviewed activation is a finding: %+v", report.deviations)
			d := findings[0].detail
			assert.Contains(t, d, fmt.Sprintf("#%d (project 7, activated ", stale))
			assert.Contains(t, d, "1 break-glass activation(s) unreviewed past the 72h0m0s review window")
			assert.NotContains(t, d, "project 8")
			assert.NotContains(t, d, "project 9")
			assert.NotContains(t, d, "SECRET-JUSTIFICATION", "no activation content in the report")
			assert.NotContains(t, d, "independent review impossible")
			return nil
		})
		require.NoError(t, err)
	})
}

func TestCollectBreakGlassReviewPosture_InsideWindowAndReviewedAreClean(t *testing.T) {
	breakGlassPostureBackends(t, func(t *testing.T, cfg *config.Config) {
		err := withUsableStorage(cfg, func(store corestorage.Storage) error {
			ctx := context.Background()
			a1 := seedAdmin(ctx, t, store, "alice")
			seedAdmin(ctx, t, store, "bob")
			seedActivation(ctx, t, store, a1.ID, 8, time.Hour, false)
			seedActivation(ctx, t, store, a1.ID, 9, 100*time.Hour, true)

			report := &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, core.NewKeyorixCore(store), report)
			assert.Empty(t, breakGlassFindings(report), "got %+v", report.deviations)
			return nil
		})
		require.NoError(t, err)
	})
}

// A degraded activation is listed whatever its age (the storage query does
// so), so one inside the window is a finding, tagged degraded, and the line
// does not call it merely "past the review window".
func TestCollectBreakGlassReviewPosture_DegradedInsideWindowIsTagged(t *testing.T) {
	breakGlassPostureBackends(t, func(t *testing.T, cfg *config.Config) {
		err := withUsableStorage(cfg, func(store corestorage.Storage) error {
			ctx := context.Background()
			a1 := seedAdmin(ctx, t, store, "alice")
			seedAdmin(ctx, t, store, "bob")

			got, err := store.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
				ProjectID: 7, UserID: a1.ID, RoleName: "project_developer",
				Justification: "SECRET-JUSTIFICATION-MUST-NOT-APPEAR", State: "expired",
				CreatedAt: time.Now().Add(-time.Hour), Degraded: true,
			})
			require.NoError(t, err)

			report := &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, core.NewKeyorixCore(store), report)
			findings := breakGlassFindings(report)
			require.Len(t, findings, 1, "a degraded activation inside the window is a finding: %+v", report.deviations)
			d := findings[0].detail
			assert.Contains(t, d, "review window (break_glass.review_window) or degraded")
			assert.Contains(t, d, fmt.Sprintf("#%d (project 7, activated ", got.ID))
			assert.Contains(t, d, ", degraded)")
			assert.NotContains(t, d, "SECRET-JUSTIFICATION")
			return nil
		})
		require.NoError(t, err)
	})
}

// One admin fires "independent review impossible" with no activations at all,
// and still when every activation has been reviewed; two admins do not.
func TestCollectBreakGlassReviewPosture_IndependentReviewImpossible(t *testing.T) {
	breakGlassPostureBackends(t, func(t *testing.T, cfg *config.Config) {
		err := withUsableStorage(cfg, func(store corestorage.Storage) error {
			ctx := context.Background()
			svc := core.NewKeyorixCore(store)

			// No admin at all: not "exactly one".
			report := &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, svc, report)
			assert.Empty(t, breakGlassFindings(report))

			a1 := seedAdmin(ctx, t, store, "alice")
			report = &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, svc, report)
			findings := breakGlassFindings(report)
			require.Len(t, findings, 1, "got %+v", report.deviations)
			assert.Contains(t, findings[0].detail, "independent review impossible")
			assert.Contains(t, findings[0].detail, "alice")
			// Core refuses self-review (ErrBreakGlassSelfReview): the finding
			// must say so, never claim activations are self-reviewed.
			assert.Contains(t, findings[0].detail, "self-review is refused")
			assert.NotContains(t, findings[0].detail, "reviewed by the person who activated it")

			// Every activation reviewed: the finding stays.
			seedActivation(ctx, t, store, a1.ID, 9, 100*time.Hour, true)
			report = &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, svc, report)
			findings = breakGlassFindings(report)
			require.Len(t, findings, 1, "got %+v", report.deviations)
			assert.Contains(t, findings[0].detail, "independent review impossible")

			// A second administrator removes it.
			seedAdmin(ctx, t, store, "bob")
			report = &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, svc, report)
			assert.Empty(t, breakGlassFindings(report), "got %+v", report.deviations)
			return nil
		})
		require.NoError(t, err)
	})
}

// With break_glass disabled nothing can be activated, so a single-admin install
// is not flagged (as collectTLSPosture skips a disabled listener); an
// activation left unreviewed from before it was switched off still is.
func TestCollectBreakGlassReviewPosture_DisabledFeature(t *testing.T) {
	breakGlassPostureBackends(t, func(t *testing.T, cfg *config.Config) {
		cfg.BreakGlass.Enabled = false
		err := withUsableStorage(cfg, func(store corestorage.Storage) error {
			ctx := context.Background()
			a1 := seedAdmin(ctx, t, store, "alice")
			svc := core.NewKeyorixCore(store)

			report := &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, svc, report)
			assert.Empty(t, breakGlassFindings(report), "single admin, feature off: got %+v", report.deviations)

			seedActivation(ctx, t, store, a1.ID, 7, 100*time.Hour, false)
			report = &postureReport{}
			collectBreakGlassReviewPosture(ctx, cfg, svc, report)
			findings := breakGlassFindings(report)
			require.Len(t, findings, 1, "got %+v", report.deviations)
			assert.Contains(t, findings[0].detail, "project 7")
			return nil
		})
		require.NoError(t, err)
	})
}

// A storage failure must surface as a deviation, never as a clean pass, and
// the independent-review check after it must still run.
func TestCollectBreakGlassReviewPosture_QueryErrorIsADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.BreakGlass.Enabled = true
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "posture.db")
	require.NoError(t, i18n.InitializeForTesting())

	require.NoError(t, withUsableStorage(cfg, func(store corestorage.Storage) error {
		ctx := context.Background()
		seedAdmin(ctx, t, store, "alice")
		failing := storagetest.Hooked(store, &storagetest.StoreHooks{
			ListUnreviewedBreakGlassActivationsBefore: func(corestorage.Storage, context.Context, time.Time) ([]*models.BreakGlassActivation, error) {
				return nil, errors.New("connection refused")
			},
		})

		report := &postureReport{}
		collectBreakGlassReviewPosture(ctx, cfg, core.NewKeyorixCore(failing), report)
		findings := breakGlassFindings(report)
		require.Len(t, findings, 2, "a failing query must not read as a clean report: %+v", report.deviations)
		assert.Contains(t, findings[0].detail, "NOT evaluated")
		assert.Contains(t, findings[0].detail, "connection refused")
		assert.Contains(t, findings[1].detail, "independent review impossible")
		return nil
	}))
}

// ListGlobalAdminHolders failing (the global role-assignment read) is a
// "NOT evaluated" deviation, never read as "not exactly one admin".
func TestCollectBreakGlassReviewPosture_AdminListErrorIsADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.BreakGlass.Enabled = true
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "posture.db")
	require.NoError(t, i18n.InitializeForTesting())

	require.NoError(t, withUsableStorage(cfg, func(store corestorage.Storage) error {
		ctx := context.Background()
		seedAdmin(ctx, t, store, "alice")
		failing := storagetest.Hooked(store, &storagetest.StoreHooks{
			ListProjectRoleAssignments: func(corestorage.Storage, context.Context, uint) ([]corestorage.RoleAssignment, error) {
				return nil, errors.New("connection refused")
			},
		})

		report := &postureReport{}
		collectBreakGlassReviewPosture(ctx, cfg, core.NewKeyorixCore(failing), report)
		findings := breakGlassFindings(report)
		require.Len(t, findings, 1, "a failing admin list must not read as a clean report: %+v", report.deviations)
		assert.Contains(t, findings[0].detail, "could not list administrators")
		assert.Contains(t, findings[0].detail, "NOT evaluated")
		assert.Contains(t, findings[0].detail, "connection refused")
		assert.NotContains(t, findings[0].detail, "independent review impossible")
		return nil
	}))
}

func TestCollectTLSPosture_ReportsTLSModeInformationally(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{"", "HTTP listener TLS mode: default (TLS 1.2 floor"},
		{config.TLSModeStrict, "HTTP listener TLS mode: strict (TLS 1.3 only)"},
	}
	for _, tc := range cases {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Server.HTTP.Enabled = true
			cfg.Server.HTTP.TLS.Enabled = true
			cfg.Server.HTTP.TLSMode = tc.mode

			report := &postureReport{}
			collectTLSPosture(cfg, report)

			assert.Empty(t, report.deviations, "neither TLS mode is a deviation (ADR-112)")
			require.Len(t, report.informational, 1)
			assert.Contains(t, report.informational[0], tc.want)
		})
	}
}
