package store

// SQLITE-UTC-NOWFUNC-1 item 4. TouchSession, TouchPersonalAccessToken and
// TouchMachineIdentityCredential (the three kinds the last-used coalescer,
// internal/core/last_used_coalescer.go, writes) store their time with
// UpdateColumn, which runs no BeforeSave hook and no NowFunc, so the column holds
// whatever zone the caller's time carries (core passes its clock's time, the host
// zone). On the production SQLite dialect a fixed-zone time is stored as
// "... +1400 OT" text that neither scans back into a *time.Time nor orders
// against UTC bounds. The writers normalise.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// touchKind is one last-used writer: create a row, touch it, read it back.
// touchKinds lists every kind the coalescer writes; a new kind belongs here.
type touchKind struct {
	name, table, column string
	create              func(w ppWorld) uint
	touch               func(ctx context.Context, ls *LocalStorage, id uint, at time.Time) error
	read                func(ctx context.Context, ls *LocalStorage, id uint) (*time.Time, error)
}

var touchKinds = []touchKind{
	{
		name: "session", table: "sessions", column: "last_seen_at",
		create: func(w ppWorld) uint {
			s := &models.Session{UserID: w.user(), SessionToken: w.name("sess-hash")}
			require.NoError(w.t, w.ls.db.Create(s).Error)
			return s.ID
		},
		touch: func(ctx context.Context, ls *LocalStorage, id uint, at time.Time) error {
			return ls.TouchSession(ctx, id, at, 0)
		},
		read: func(ctx context.Context, ls *LocalStorage, id uint) (*time.Time, error) {
			s, err := ls.GetSessionByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return s.LastSeenAt, nil
		},
	},
	{
		name: "pat", table: "personal_access_tokens", column: "last_used_at",
		create: func(w ppWorld) uint {
			pat := &models.PersonalAccessToken{UserID: w.user(), Name: w.name("pat"), TokenHash: w.name("pat-hash"), TokenPrefix: "kx_pat_", CreatedAt: time.Now().UTC().Add(-time.Hour)}
			require.NoError(w.t, w.ls.db.Create(pat).Error)
			return pat.ID
		},
		touch: func(ctx context.Context, ls *LocalStorage, id uint, at time.Time) error {
			return ls.TouchPersonalAccessToken(ctx, id, at, 0)
		},
		read: func(ctx context.Context, ls *LocalStorage, id uint) (*time.Time, error) {
			p, err := ls.GetPersonalAccessTokenByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return p.LastUsedAt, nil
		},
	},
	{
		name: "machine-credential", table: "machine_identity_credentials", column: "last_used_at",
		create: func(w ppWorld) uint {
			cred := &models.MachineIdentityCredential{MachineIdentityID: w.machine(w.project()), Name: w.name("cred"), TokenHash: w.name("cred-hash"), TokenPrefix: "kx_machine_", CreatedAt: time.Now().UTC().Add(-time.Hour), Classification: "internal"}
			require.NoError(w.t, w.ls.db.Create(cred).Error)
			return cred.ID
		},
		touch: func(ctx context.Context, ls *LocalStorage, id uint, at time.Time) error {
			return ls.TouchMachineIdentityCredential(ctx, id, at, 0)
		},
		read: func(ctx context.Context, ls *LocalStorage, id uint) (*time.Time, error) {
			c, err := ls.GetMachineIdentityCredentialByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return c.LastUsedAt, nil
		},
	},
}

func newTouchStorage(t *testing.T, backend string) *LocalStorage {
	t.Helper()
	ls, _ := newPrincipalPermStorage(t, backend)
	require.NoError(t, ls.db.AutoMigrate(&models.Session{}, &models.PersonalAccessToken{}, &models.MachineIdentityCredential{}))
	return ls
}

func TestTouchLastUsedStoresUTC(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		for _, k := range touchKinds {
			t.Run(backend+"/"+k.name, func(t *testing.T) {
				ls := newTouchStorage(t, backend)
				w := ppWorld{t: t, ls: ls}
				ctx := context.Background()

				zone := time.FixedZone("OT", 14*3600)
				usedAt := time.Now().In(zone)
				id := k.create(w)

				require.NoError(t, k.touch(ctx, ls, id, usedAt))
				got, err := k.read(ctx, ls, id)
				require.NoError(t, err, "a touched %s must scan back", k.name)
				require.NotNil(t, got)
				require.WithinDuration(t, usedAt, *got, time.Millisecond)

				// A second touch compares against the stored value (column < cutoff).
				later := usedAt.Add(time.Minute)
				require.NoError(t, k.touch(ctx, ls, id, later))
				got, err = k.read(ctx, ls, id)
				require.NoError(t, err)
				require.NotNil(t, got)
				require.WithinDuration(t, later, *got, time.Millisecond, "the later touch must replace the earlier value")

				if backend != "sqlite" {
					return
				}
				var typ, val sql.NullString
				require.NoError(t, ls.db.Raw("SELECT typeof("+k.column+"), "+k.column+" FROM "+k.table+" WHERE id = ?", id).Row().Scan(&typ, &val))
				require.NotContains(t, val.String, "OT", "%s.%s stored with a zone name: %s", k.table, k.column, val.String)
				require.NotContains(t, val.String, "+14", "%s.%s stored with an offset: %s", k.table, k.column, val.String)
			})
		}
	}
}

// The hygiene stale counts compare last_used_at (stored UTC by the Touch writers)
// with a threshold core derives from c.now() in the host zone
// (internal/core/hygiene_trends.go). On SQLite that comparison is on the stored
// text, so a zoned threshold miscounts by the host's offset unless the Count
// functions normalise it.
func TestHygieneStaleCountsHostZoneThreshold(t *testing.T) {
	const window = time.Hour
	zones := []*time.Location{time.FixedZone("OT", 14*3600), time.FixedZone("NT", -(3*3600 + 1800))}
	for _, backend := range principalPermBackends(t) {
		for _, zone := range zones {
			for _, c := range []struct {
				name      string
				usedAgo   time.Duration
				wantStale int
			}{
				{"used-1m-ago", time.Minute, 0},
				{"used-2h-ago", 2 * time.Hour, 1},
			} {
				t.Run(backend+"/"+zone.String()+"/"+c.name, func(t *testing.T) {
					ls := newTouchStorage(t, backend)
					w := ppWorld{t: t, ls: ls}
					ctx := context.Background()
					now := time.Now().In(zone)
					usedAt := now.Add(-c.usedAgo)

					pat := touchKinds[1].create(w)
					require.NoError(t, ls.TouchPersonalAccessToken(ctx, pat, usedAt, 0))
					cred := touchKinds[2].create(w)
					require.NoError(t, ls.TouchMachineIdentityCredential(ctx, cred, usedAt, 0))

					threshold := now.Add(-window)
					n, err := ls.CountStalePATs(ctx, threshold)
					require.NoError(t, err)
					require.Equal(t, c.wantStale, n, "CountStalePATs, PAT used %s before a %s-zone threshold %s", c.usedAgo, zone, window)
					n, err = ls.CountStaleMachineCredentials(ctx, threshold)
					require.NoError(t, err)
					require.Equal(t, c.wantStale, n, "CountStaleMachineCredentials, credential used %s before a %s-zone threshold %s", c.usedAgo, zone, window)
				})
			}
		}
	}
}
