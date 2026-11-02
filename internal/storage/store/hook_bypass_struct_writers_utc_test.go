package store

// UTC-STORE-WRITERS-1 item 2. More rows for TestHookBypassTimeWriters_StoreUTCOnNonUTCHost
// (hook_bypass_time_writers_utc_test.go): the hook-bypassing writers that take a
// time inside a struct (Model(&X{}).Select(...).Updates(x)), through an upsert
// (clause.OnConflict DoUpdates) or as a caller-supplied expiry column. Same
// mechanism: the test re-runs itself under TZ=Asia/Kolkata and reads the column
// back raw (SQLite text) or as a timestamp (Postgres).

import (
	"context"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// hostZoneSkew is how far from "now" a row's stored value is expected to land, for
// the rows that must write a future expiry (a share or dynamic lease refuses a past one).
var hostZoneSkew = map[string]time.Duration{
	"UpdateShareRecord expires_at":                              time.Hour,
	"CreateShareRecord re-share expires_at (applyShareRequest)": time.Hour,
	"ExtendDynamicSecretLeaseExpiry":                            time.Hour,
	"UpdateProjectInvitation expires_at":                        time.Hour,
	"UpdateAccessRequest expires_at":                            time.Hour,
}

func init() {
	future := func(_ string, at time.Time) time.Time { return at.Add(time.Hour) }

	hostZoneWriters = append(hostZoneWriters,
		hostZoneWriter{"UpdateShareRecord expires_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			s := seedShare(w)
			exp := future("UpdateShareRecord expires_at", at)
			_, err := w.ls.UpdateShareRecord(ctx, &models.ShareRecord{ID: s.ID, SecretID: s.SecretID, OwnerID: s.OwnerID, RecipientID: s.RecipientID, Permission: "write", ExpiresAt: &exp})
			require.NoError(w.t, err)
			return "share_records", "expires_at", s.ID
		}},
		hostZoneWriter{"CreateShareRecord re-share expires_at (applyShareRequest)", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			s := seedShare(w)
			exp := future("CreateShareRecord re-share expires_at (applyShareRequest)", at)
			matched, err := applyShareRequest(w.ls.db.WithContext(ctx), s, &models.ShareRecord{Permission: "write", ExpiresAt: &exp})
			require.NoError(w.t, err)
			require.True(w.t, matched)
			return "share_records", "expires_at", s.ID
		}},
		hostZoneWriter{"ExtendDynamicSecretLeaseExpiry", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			l := &models.DynamicSecretLease{LeaseID: w.name("lease"), Status: "active", IssuedAt: at.UTC(), ExpiresAt: at.UTC().Add(time.Minute)}
			require.NoError(w.t, w.ls.db.Create(l).Error)
			ok, err := w.ls.ExtendDynamicSecretLeaseExpiry(ctx, l.LeaseID, future("ExtendDynamicSecretLeaseExpiry", at))
			require.NoError(w.t, err)
			require.True(w.t, ok)
			return "dynamic_secret_leases", "expires_at", l.ID
		}},
		hostZoneWriter{"TransitionDynamicSecretConfigDisabled", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			c := seedDynamicConfig(w)
			c.Disabled = true
			c.UpdatedAt = at
			ok, err := w.ls.TransitionDynamicSecretConfigDisabled(ctx, c, false)
			require.NoError(w.t, err)
			require.True(w.t, ok)
			return "dynamic_secret_configs", "updated_at", c.ID
		}},
		hostZoneWriter{"SettleBreakGlassOwedAudit", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			a := seedBreakGlass(w)
			require.NoError(w.t, w.ls.db.Model(&models.BreakGlassActivation{}).Where("id = ?", a.ID).Update("degraded", true).Error)
			ok, err := w.ls.SettleBreakGlassOwedAudit(ctx, a.ID, at)
			require.NoError(w.t, err)
			require.True(w.t, ok)
			return "break_glass_activations", "audit_settled_at", a.ID
		}},
		hostZoneWriter{"UpdateProjectInvitation expires_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			inv := seedInvitation(w)
			exp := future("UpdateProjectInvitation expires_at", at)
			inv.ExpiresAt = &exp
			updateInvitation(ctx, w, inv)
			return "project_invitations", "expires_at", inv.ID
		}},
		hostZoneWriter{"UpdateProjectInvitation accepted_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			inv := seedInvitation(w)
			inv.State, inv.AcceptedAt = "accepted", &at
			updateInvitation(ctx, w, inv)
			return "project_invitations", "accepted_at", inv.ID
		}},
		hostZoneWriter{"UpdateProjectInvitation revoked_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			inv := seedInvitation(w)
			inv.State, inv.RevokedAt = "revoked", &at
			updateInvitation(ctx, w, inv)
			return "project_invitations", "revoked_at", inv.ID
		}},
		hostZoneWriter{"UpdateAccessRequest expires_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			r := seedAccessRequest(w)
			exp := future("UpdateAccessRequest expires_at", at)
			r.State, r.ExpiresAt = "approved", &exp
			updateAccessRequest(ctx, w, r)
			return "access_requests", "expires_at", r.ID
		}},
		hostZoneWriter{"UpdateAccessRequest resolved_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			r := seedAccessRequest(w)
			r.State, r.ResolvedAt = "approved", &at
			updateAccessRequest(ctx, w, r)
			return "access_requests", "resolved_at", r.ID
		}},
		hostZoneWriter{"TransitionMachineIdentityState revoked_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			m := seedMachine(w)
			m.State, m.RevokedAt, m.UpdatedAt = "revoked", &at, at
			transitionMachine(ctx, w, m)
			return "machine_identities", "revoked_at", m.ID
		}},
		hostZoneWriter{"TransitionMachineIdentityState updated_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			m := seedMachine(w)
			m.State, m.UpdatedAt = "revoked", at
			transitionMachine(ctx, w, m)
			return "machine_identities", "updated_at", m.ID
		}},
		hostZoneWriter{"SetSystemMetadata", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, any) {
			key := w.name("pp-meta")
			require.NoError(w.t, w.ls.SetSystemMetadata(ctx, key, "v"))
			return "system_metadata", "updated_at", key
		}},
		hostZoneWriter{"SetRecoveryKeyRecord rotated_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			rec := &models.RecoveryKeyRecord{KeyHash: "h", KeyVersion: 1, RotatedAt: &at}
			require.NoError(w.t, w.ls.SetRecoveryKeyRecord(ctx, rec))
			return "recovery_key_records", "rotated_at", rec.ID
		}},
		hostZoneWriter{"CreateOrUpdateSecretACL insert updated_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			acl := &models.SecretACL{SecretID: seedSecret(w).ID, UserID: w.user(), Permissions: `["secrets.read"]`, GrantedBy: w.user(), UpdatedAt: at}
			require.NoError(w.t, w.ls.CreateOrUpdateSecretACL(ctx, acl))
			return "secret_acls", "updated_at", acl.ID
		}},
		hostZoneWriter{"CreateOrUpdateSecretACL upsert updated_at", func(ctx context.Context, w ppWorld, at time.Time) (string, string, any) {
			secretID, userID := seedSecret(w).ID, w.user()
			first := &models.SecretACL{SecretID: secretID, UserID: userID, Permissions: `["secrets.read"]`, GrantedBy: userID}
			require.NoError(w.t, w.ls.CreateOrUpdateSecretACL(ctx, first))
			second := &models.SecretACL{SecretID: secretID, UserID: userID, Permissions: `["secrets.write"]`, GrantedBy: userID, UpdatedAt: at}
			require.NoError(w.t, w.ls.CreateOrUpdateSecretACL(ctx, second))
			return "secret_acls", "updated_at", first.ID
		}},
	)
}

func seedInvitation(w ppWorld) *models.ProjectInvitation {
	inv := &models.ProjectInvitation{ProjectID: w.project(), Email: w.name("pp-invitee") + "@example.com", Role: "viewer", State: invitationStatePending}
	require.NoError(w.t, w.ls.db.Create(inv).Error)
	return inv
}

func updateInvitation(ctx context.Context, w ppWorld, inv *models.ProjectInvitation) {
	ok, err := w.ls.UpdateProjectInvitation(ctx, inv)
	require.NoError(w.t, err)
	require.True(w.t, ok)
}

func seedAccessRequest(w ppWorld) *models.AccessRequest {
	r := &models.AccessRequest{ProjectID: w.project(), UserID: w.user(), SuggestedRole: "viewer", State: accessRequestStatePending}
	require.NoError(w.t, w.ls.db.Create(r).Error)
	return r
}

func updateAccessRequest(ctx context.Context, w ppWorld, r *models.AccessRequest) {
	ok, err := w.ls.UpdateAccessRequest(ctx, r)
	require.NoError(w.t, err)
	require.True(w.t, ok)
}

func seedMachine(w ppWorld) *models.MachineIdentity {
	m := &models.MachineIdentity{Name: w.name("pp-mi"), ProjectID: w.project(), State: machineIdentityStateActive}
	require.NoError(w.t, w.ls.db.Create(m).Error)
	return m
}

func transitionMachine(ctx context.Context, w ppWorld, m *models.MachineIdentity) {
	ok, err := w.ls.TransitionMachineIdentityState(ctx, m, machineIdentityStateActive)
	require.NoError(w.t, err)
	require.True(w.t, ok)
}
