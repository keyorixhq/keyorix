package store

// SQLITE-UTC-NOWFUNC-1 item 4. TouchPersonalAccessToken and
// TouchMachineIdentityCredential write last_used_at with UpdateColumn, which runs
// no BeforeSave hook and no NowFunc, so the column holds whatever zone the caller's
// time carries (core passes c.now(), the host zone). On the production SQLite
// dialect a fixed-zone time is stored as "... +1400 OT" text that neither scans
// back into a *time.Time nor orders against UTC bounds. The writers normalise.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestTouchLastUsedStoresUTC(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorage(t, backend)
			require.NoError(t, ls.db.AutoMigrate(&models.PersonalAccessToken{}, &models.MachineIdentityCredential{}))
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()

			zone := time.FixedZone("OT", 14*3600)
			usedAt := time.Now().In(zone)
			created := time.Now().UTC().Add(-time.Hour)

			pat := &models.PersonalAccessToken{UserID: w.user(), Name: w.name("pat"), TokenHash: w.name("pat-hash"), TokenPrefix: "kx_pat_", CreatedAt: created}
			require.NoError(t, ls.db.Create(pat).Error)
			cred := &models.MachineIdentityCredential{MachineIdentityID: w.machine(w.project()), Name: w.name("cred"), TokenHash: w.name("cred-hash"), TokenPrefix: "kx_machine_", CreatedAt: created, Classification: "internal"}
			require.NoError(t, ls.db.Create(cred).Error)

			require.NoError(t, ls.TouchPersonalAccessToken(ctx, pat.ID, usedAt, 0))
			require.NoError(t, ls.TouchMachineIdentityCredential(ctx, cred.ID, usedAt, 0))

			gotPAT, err := ls.GetPersonalAccessTokenByID(ctx, pat.ID)
			require.NoError(t, err, "a touched PAT must scan back")
			require.NotNil(t, gotPAT.LastUsedAt)
			require.WithinDuration(t, usedAt, *gotPAT.LastUsedAt, time.Millisecond)

			gotCred, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
			require.NoError(t, err, "a touched machine credential must scan back")
			require.NotNil(t, gotCred.LastUsedAt)
			require.WithinDuration(t, usedAt, *gotCred.LastUsedAt, time.Millisecond)

			// A second touch compares against the stored value (last_used_at < cutoff).
			later := usedAt.Add(time.Minute)
			require.NoError(t, ls.TouchPersonalAccessToken(ctx, pat.ID, later, 0))
			require.NoError(t, ls.TouchMachineIdentityCredential(ctx, cred.ID, later, 0))
			gotPAT, err = ls.GetPersonalAccessTokenByID(ctx, pat.ID)
			require.NoError(t, err)
			require.WithinDuration(t, later, *gotPAT.LastUsedAt, time.Millisecond, "the later touch must replace the earlier value")

			if backend != "sqlite" {
				return
			}
			for _, q := range []struct{ table, id string }{{"personal_access_tokens", "pat"}, {"machine_identity_credentials", "cred"}} {
				id := pat.ID
				if q.id == "cred" {
					id = cred.ID
				}
				var typ, val sql.NullString
				require.NoError(t, ls.db.Raw("SELECT typeof(last_used_at), last_used_at FROM "+q.table+" WHERE id = ?", id).Row().Scan(&typ, &val))
				require.NotContains(t, val.String, "OT", "%s.last_used_at stored with a zone name: %s", q.table, val.String)
				require.NotContains(t, val.String, "+14", "%s.last_used_at stored with an offset: %s", q.table, val.String)
			}
		})
	}
}
