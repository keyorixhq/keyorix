package store

// STORE-STALE-TAILS-2 item 3. The writers below persist a time through
// Updates(map) / UpdateColumn(s) / Update(col, v), which run no BeforeSave hook
// and no GORM NowFunc: the column holds whatever zone the time carries. Core
// hands them its clock (c.now(), time.Now in the host zone), and three of them
// call time.Now() themselves. On SQLite a non-UTC time is stored as text with
// the host offset, which does not order against the UTC values NowFunc and the
// hooks write (SQLite compares the text). Each writer normalises to UTC; the
// Touch* writers (touch_last_used_utc_test.go) and the passkey counter write
// are covered elsewhere.
//
// The test re-runs itself in a child process with TZ=Asia/Kolkata (+05:30), so
// time.Now() is a host-zone time exactly as on a server outside UTC. No test
// assigns time.Local (no_time_local_assignment_guard_test.go).

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	hostZoneWriterChildEnv = "KEYORIX_STORE_HOST_ZONE_WRITER_CHILD"
	hostZoneWriterTZ       = "Asia/Kolkata"
)

// hostZoneWriter is one hook-bypassing time writer: seed a row, call the writer
// with at (the caller's clock), and name the row and column it wrote.
type hostZoneWriter struct {
	name  string
	write func(ctx context.Context, w ppWorld, at time.Time) (table, column string, id uint)
}

var hostZoneWriters = []hostZoneWriter{
	{"UpdateShareRecord", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, uint) {
		s := seedShare(w)
		_, err := w.ls.UpdateShareRecord(ctx, &models.ShareRecord{ID: s.ID, SecretID: s.SecretID, OwnerID: s.OwnerID, RecipientID: s.RecipientID, Permission: "write"})
		require.NoError(w.t, err)
		return "share_records", "updated_at", s.ID
	}},
	{"CreateShareRecord re-share (applyShareRequest)", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, uint) {
		s := seedShare(w)
		matched, err := applyShareRequest(w.ls.db.WithContext(ctx), s, &models.ShareRecord{Permission: "write"})
		require.NoError(w.t, err)
		require.True(w.t, matched)
		return "share_records", "updated_at", s.ID
	}},
	{"SetDynamicSecretConfigAdminDSN", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, uint) {
		c := seedDynamicConfig(w)
		require.NoError(w.t, w.ls.SetDynamicSecretConfigAdminDSN(ctx, c.ID, []byte("enc"), []byte("meta")))
		return "dynamic_secret_configs", "updated_at", c.ID
	}},
	{"SetDynamicSecretConfigClassification", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		c := seedDynamicConfig(w)
		ok, err := w.ls.SetDynamicSecretConfigClassification(ctx, c.ID, "", "internal", at)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "dynamic_secret_configs", "updated_at", c.ID
	}},
	{"RecordDynamicSecretLeaseRevocation", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		l := &models.DynamicSecretLease{LeaseID: w.name("lease"), Status: "active", IssuedAt: at.UTC(), ExpiresAt: at.UTC().Add(time.Hour)}
		require.NoError(w.t, w.ls.db.Create(l).Error)
		ok, err := w.ls.RecordDynamicSecretLeaseRevocation(ctx, l.LeaseID, "revoked", "manual", "", &at)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "dynamic_secret_leases", "revoked_at", l.ID
	}},
	{"RevokeBreakGlassActivation", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		a := seedBreakGlass(w)
		require.NoError(w.t, w.ls.RevokeBreakGlassActivation(ctx, a.ID, a.UserID, 0, at))
		return "break_glass_activations", "revoked_at", a.ID
	}},
	{"ReviewBreakGlassActivation", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		a := seedBreakGlass(w)
		require.NoError(w.t, w.ls.ReviewBreakGlassActivation(ctx, a.ID, a.UserID, "ok", at))
		return "break_glass_activations", "reviewed_at", a.ID
	}},
	{"TryAcquireSchedulerLock create", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, uint) {
		key := ppSeq.Add(1)
		ok, err := w.ls.TryAcquireSchedulerLock(ctx, key, "holder-a", time.Millisecond)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "scheduler_lock_leases", "expires_at", uint(key)
	}},
	{"TryAcquireSchedulerLock reclaim", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, uint) {
		key := ppSeq.Add(1)
		require.NoError(w.t, w.ls.db.Create(&models.SchedulerLockLease{Key: key, Holder: "holder-a", ExpiresAt: time.Now().UTC().Add(-time.Hour)}).Error)
		ok, err := w.ls.TryAcquireSchedulerLock(ctx, key, "holder-b", time.Millisecond)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "scheduler_lock_leases", "expires_at", uint(key)
	}},
	{"UpdateAlertEscalationPolicy", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		p := &models.AlertEscalationPolicy{Name: w.name("esc"), MinSeverity: "high", EscalateAfterMinutes: 5}
		require.NoError(w.t, w.ls.db.Create(p).Error)
		p.EscalateAfterMinutes = 10
		p.UpdatedAt = at
		require.NoError(w.t, w.ls.UpdateAlertEscalationPolicy(ctx, p))
		return "alert_escalation_policies", "updated_at", p.ID
	}},
	{"UpdateSecretTemplateFields", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		tpl := &models.SecretTemplate{Name: w.name("tpl")}
		require.NoError(w.t, w.ls.db.Create(tpl).Error)
		ok, err := w.ls.UpdateSecretTemplateFields(ctx, tpl.ID, storage.SecretTemplateFieldUpdate{Name: tpl.Name, Description: "d"}, at)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "secret_templates", "updated_at", tpl.ID
	}},
	{"UpdateRotationPolicyFields", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		p := &models.RotationPolicy{Name: w.name("rp"), Scope: "project", IntervalDays: 30, CreatedBy: "t"}
		require.NoError(w.t, w.ls.db.Create(p).Error)
		ok, err := w.ls.UpdateRotationPolicyFields(ctx, p.ID, storage.RotationPolicyFieldUpdate{Name: p.Name, IntervalDays: 60, IsActive: true}, at)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "rotation_policies", "updated_at", p.ID
	}},
	{"ReactivateMachineIdentitiesForRestoredProject", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		deletedAt := at.UTC().Add(-time.Minute)
		p := &models.Project{Name: w.name("pp-project"), DeletedAt: gorm.DeletedAt{Time: deletedAt, Valid: true}}
		require.NoError(w.t, w.ls.db.Create(p).Error)
		m := &models.MachineIdentity{Name: w.name("mi"), ProjectID: p.ID, State: machineIdentityStateSuspended,
			CascadeSuspendedProjectID: p.ID, CascadeSuspendedAt: &deletedAt, UpdatedAt: deletedAt}
		require.NoError(w.t, w.ls.db.Create(m).Error)
		got, err := w.ls.ReactivateMachineIdentitiesForRestoredProject(ctx, p.ID, at)
		require.NoError(w.t, err)
		require.Len(w.t, got, 1)
		return "machine_identities", "updated_at", m.ID
	}},
	{"MarkSetupTokenConsumed", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		tok := &models.SetupToken{TokenHash: w.name("setup-hash"), Purpose: "account_setup", State: "active", ExpiresAt: at.UTC().Add(time.Hour)}
		require.NoError(w.t, w.ls.db.Create(tok).Error)
		ok, err := w.ls.MarkSetupTokenConsumed(ctx, tok.ID, at)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "setup_tokens", "consumed_at", tok.ID
	}},
	{"RotateSession", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		userID := w.user()
		exp := at.UTC().Add(time.Hour)
		old := &models.Session{UserID: userID, SessionToken: w.name("sess-old"), ExpiresAt: &exp}
		require.NoError(w.t, w.ls.db.Create(old).Error)
		_, won, err := w.ls.RotateSession(ctx, old.ID, &models.Session{UserID: userID, SessionToken: w.name("sess-new"), ExpiresAt: &exp}, at)
		require.NoError(w.t, err)
		require.True(w.t, won)
		return "sessions", "rotated_at", old.ID
	}},
	{"UpdateSecretRotationConfig", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		s := seedSecret(w)
		ok, err := w.ls.UpdateSecretRotationConfig(ctx, &models.SecretNode{ID: s.ID, ProjectID: s.ProjectID, AutoRotate: true, RotationLength: 32, UpdatedAt: at}, "")
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "secret_nodes", "updated_at", s.ID
	}},
	{"SetSecretCertNotAfter", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		s := seedSecret(w)
		require.NoError(w.t, w.ls.SetSecretCertNotAfter(ctx, s.ID, &at))
		return "secret_nodes", "cert_not_after", s.ID
	}},
	{"UpdateSecretFields updated_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		s := seedSecret(w)
		ok, err := w.ls.UpdateSecretFields(ctx, s.ID, storage.SecretFieldUpdate{UpdatedAt: &at})
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "secret_nodes", "updated_at", s.ID
	}},
	{"UpdateSecretFields last_rotated_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		s := seedSecret(w)
		ok, err := w.ls.UpdateSecretFields(ctx, s.ID, storage.SecretFieldUpdate{SetLastRotatedAt: true, LastRotatedAt: &at})
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "secret_nodes", "last_rotated_at", s.ID
	}},
	{"UpdateProjectFields", func(ctx context.Context, w ppWorld, at time.Time) (string, string, uint) {
		id := w.project()
		ok, err := w.ls.UpdateProjectFields(ctx, id, w.name("pp-project"), "d", nil, at)
		require.NoError(w.t, err)
		require.True(w.t, ok)
		return "projects", "updated_at", id
	}},
}

func seedSecret(w ppWorld) *models.SecretNode {
	s := &models.SecretNode{Name: w.name("secret"), ProjectID: w.project(), Type: "generic", OwnerID: w.user()}
	require.NoError(w.t, w.ls.db.Create(s).Error)
	return s
}

func seedShare(w ppWorld) *models.ShareRecord {
	s := &models.ShareRecord{SecretID: seedSecret(w).ID, OwnerID: w.user(), RecipientID: w.user(), Permission: "read"}
	require.NoError(w.t, w.ls.db.Create(s).Error)
	return s
}

func seedDynamicConfig(w ppWorld) *models.DynamicSecretConfig {
	c := &models.DynamicSecretConfig{Name: w.name("dyn"), ProjectID: w.project(), BackendType: "postgres"}
	require.NoError(w.t, w.ls.db.Create(c).Error)
	return c
}

func seedBreakGlass(w ppWorld) *models.BreakGlassActivation {
	exp := time.Now().UTC().Add(time.Hour)
	a := &models.BreakGlassActivation{ProjectID: w.project(), UserID: w.user(), RoleName: "admin", Justification: "j", State: breakGlassActiveState, ExpiresAt: &exp}
	require.NoError(w.t, w.ls.db.Create(a).Error)
	return a
}

func TestHookBypassTimeWriters_StoreUTCOnNonUTCHost(t *testing.T) {
	if os.Getenv(hostZoneWriterChildEnv) == "" {
		runHostZoneWriterChild(t)
		return
	}
	_, off := time.Now().Zone()
	require.NotZero(t, off, "child must run with a non-UTC host zone (TZ=%s)", hostZoneWriterTZ)

	for _, backend := range principalPermBackends(t) {
		for _, wr := range hostZoneWriters {
			t.Run(backend+"/"+wr.name, func(t *testing.T) {
				ls, _ := newPrincipalPermStorage(t, backend)
				// Production stamps created_at/updated_at in UTC (storage factory NowFunc).
				ls.db.Config.NowFunc = func() time.Time { return time.Now().UTC() }
				require.NoError(t, ls.db.AutoMigrate(&models.ShareRecord{}, &models.SecretNode{},
					&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.BreakGlassActivation{},
					&models.SchedulerLockLease{}, &models.AlertEscalationPolicy{}, &models.SecretTemplate{},
					&models.RotationPolicy{}, &models.SetupToken{}, &models.Session{}))
				ctx := context.Background()

				before := time.Now().Add(-time.Second)
				table, column, id := wr.write(ctx, ppWorld{t: t, ls: ls}, time.Now())
				after := time.Now().Add(time.Second)

				key := "id"
				if table == "scheduler_lock_leases" {
					key = "key"
				}
				q := "SELECT " + column + " FROM " + table + " WHERE " + key + " = ?"
				if backend != "sqlite" {
					var got sql.NullTime
					require.NoError(t, ls.db.Raw(q, id).Row().Scan(&got))
					require.True(t, got.Valid, "%s.%s not written", table, column)
					require.True(t, !got.Time.Before(before) && !got.Time.After(after), "%s.%s = %v, want about now", table, column, got.Time)
					return
				}
				var raw sql.NullString
				require.NoError(t, ls.db.Raw(q, id).Row().Scan(&raw))
				require.True(t, raw.Valid, "%s.%s not written", table, column)
				stored, ok := parseDBTimestamp(raw.String)
				require.True(t, ok, "%s.%s stored as unparseable text %q", table, column, raw.String)
				_, storedOff := stored.Zone()
				require.Zero(t, storedOff, "%s.%s stored with the host offset: %q (want UTC)", table, column, raw.String)
				require.True(t, !stored.Before(before) && !stored.After(after), "%s.%s = %v, want about now", table, column, stored)
			})
		}
	}
}

// runHostZoneWriterChild re-executes this test binary for the test above with
// TZ=Asia/Kolkata and requires that it ran and passed.
func runHostZoneWriterChild(t *testing.T) {
	t.Helper()
	if _, err := time.LoadLocation(hostZoneWriterTZ); err != nil {
		t.Skipf("zone database has no %s: %v", hostZoneWriterTZ, err)
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TZ=") && !strings.HasPrefix(kv, hostZoneWriterChildEnv+"=") {
			env = append(env, kv)
		}
	}
	env = append(env, "TZ="+hostZoneWriterTZ, hostZoneWriterChildEnv+"=1")
	name := t.Name()
	cmd := exec.Command(exe, "-test.run=^"+name+"$", "-test.v", "-test.count=1")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	for line := range strings.Lines(string(out)) {
		if strings.Contains(line, "--- ") {
			t.Log(strings.TrimSpace(line))
		}
	}
	require.NoError(t, err, "child TZ=%s failed:\n%s", hostZoneWriterTZ, out)
	require.Contains(t, string(out), "--- PASS: "+name+" ", "child TZ=%s did not run %s:\n%s", hostZoneWriterTZ, name, out)
}
