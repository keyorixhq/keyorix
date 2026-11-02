// utc_writes_last_used_test.go -- UTC-WRITES-1 item 2.
//
// The last-used / last-seen stamps are written by UpdateColumn, which bypasses the model BeforeSave
// hooks, so nothing normalises them on the way in. Production feeds them c.now(), which is the host
// zone. Two things can go wrong on a non-UTC host, and the tests check both:
//   - the stamp is stored as host-zone text (the "stored as UTC" half);
//   - the conditional UPDATE ("only when older") compares that text with a UTC value already in the
//     row, so an older host-zone stamp overwrites a newer UTC one and the column moves backward
//     (the "never moves backward" half).
//
// The tests drive the real chain: the coalescer's record + FlushLastUsed for PAT, machine credential
// and session, persistUpdatedCredential for the WebAuthn counter. Helpers (the dialect split, the
// stored-value assertion) are in utc_writes_host_zone_test.go. Not parallel, for the same reason as
// that file.

package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (d utcDialect) openLastUsed(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db := d.open(t, &models.User{}, &models.Session{}, &models.AuditEvent{},
		&models.PersonalAccessToken{}, &models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.WebAuthnCredential{})
	seedAliceUser(t, db)
	return newSessionUTCCore(db), db
}

// lastUsedProbe is one writer under test: how to seed its row, which column it stamps and which
// coalescer key reaches it.
type lastUsedProbe struct {
	name, table, column string
	key                 func(id uint) lastUsedKey
	seed                func(t *testing.T, c *KeyorixCore, db *gorm.DB) uint
}

func lastUsedProbes() []lastUsedProbe {
	return []lastUsedProbe{
		{
			name: "personal access token", table: "personal_access_tokens", column: "last_used_at",
			key: func(id uint) lastUsedKey { return lastUsedKey{lastUsedPAT, id} },
			seed: func(t *testing.T, _ *KeyorixCore, db *gorm.DB) uint {
				pat := &models.PersonalAccessToken{UserID: 1, Name: "ci", TokenHash: "pat-hash"}
				require.NoError(t, db.Create(pat).Error)
				return pat.ID
			},
		},
		{
			name: "machine credential", table: "machine_identity_credentials", column: "last_used_at",
			key: func(id uint) lastUsedKey { return lastUsedKey{lastUsedMachineCredential, id} },
			seed: func(t *testing.T, _ *KeyorixCore, db *gorm.DB) uint {
				mi := &models.MachineIdentity{Name: "robot", State: "active"}
				require.NoError(t, db.Create(mi).Error)
				cred := &models.MachineIdentityCredential{MachineIdentityID: mi.ID, TokenHash: "mic-hash"}
				require.NoError(t, db.Create(cred).Error)
				return cred.ID
			},
		},
		{
			name: "session", table: "sessions", column: "last_seen_at",
			key: func(id uint) lastUsedKey { return lastUsedKey{lastUsedSession, id} },
			seed: func(t *testing.T, c *KeyorixCore, db *gorm.DB) uint {
				s, err := c.mintSession(context.Background(), 1, "ua", "10.0.0.1")
				require.NoError(t, err)
				// Start from NULL so the first stamp is the write under test, not the mint's.
				require.NoError(t, db.Model(&models.Session{}).Where("id = ?", s.ID).
					UpdateColumn("last_seen_at", nil).Error)
				return s.ID
			},
		},
	}
}

func stampLastUsed(t *testing.T, c *KeyorixCore, k lastUsedKey, at time.Time) {
	t.Helper()
	c.lastUsed().record(k, at)
	c.FlushLastUsed(context.Background())
}

func TestLastUsedWritesStoreUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		for _, p := range lastUsedProbes() {
			t.Run(p.name, func(t *testing.T) {
				setNonUTCHostZone(t)
				c, db := d.openLastUsed(t)
				id := p.seed(t, c, db)

				stampLastUsed(t, c, p.key(id), c.now())

				d.requireStored(t, db, p.table, p.column, utcWritesInstant, "id = ?", id)
			})
		}
	})
}

func TestLastUsedWritesNeverMoveBackward(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		for _, p := range lastUsedProbes() {
			t.Run(p.name, func(t *testing.T) {
				setNonUTCHostZone(t)
				c, db := d.openLastUsed(t)
				id := p.seed(t, c, db)

				// A newer stamp is already in the row, in UTC (a PostgreSQL-era row, another
				// replica on a UTC host, or an earlier fixed write).
				newer := utcWritesInstant.Add(30 * time.Minute)
				require.NoError(t, db.Table(p.table).Where("id = ?", id).UpdateColumn(p.column, newer).Error)

				stampLastUsed(t, c, p.key(id), c.now()) // 09:00 UTC, older than the row

				d.requireStored(t, db, p.table, p.column, newer, "id = ?", id)
			})
		}
	})
}

// The rows TouchSession later compares against start as the mint's (and RefreshSession's) own
// last_seen_at, so those must be UTC too or the first Touch orders against host-zone text.
func TestSessionMintAndRefreshStoreLastSeenAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		c, db := d.openLastUsed(t)
		ctx := context.Background()

		minted, err := c.mintSession(ctx, 1, "ua", "10.0.0.1")
		require.NoError(t, err)
		d.requireStored(t, db, "sessions", "last_seen_at", utcWritesInstant, "id = ?", minted.ID)

		refreshed, err := c.RefreshSession(ctx, minted.SessionToken)
		require.NoError(t, err)
		d.requireStored(t, db, "sessions", "last_seen_at", utcWritesInstant, "id = ?", refreshed.ID)
	})
}

// The hygiene counts range-query the columns the writers above stamp. Writers and readers must
// agree on the zone: a host-zone bound against UTC text orders by wall clock, so a token used
// one minute after the threshold counted as stale (and the reverse). This passes on main, where
// both ends were host-zone; it guards the pairing, so it goes red if only one end is changed.
func TestStaleCountsOrderAgainstUTCLastUsed(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		c, db := d.openLastUsed(t)
		ctx := context.Background()
		probes := lastUsedProbes()
		pat, mic := probes[0], probes[1]
		patID := pat.seed(t, c, db)
		micID := mic.seed(t, c, db)
		require.NoError(t, db.Model(&models.MachineIdentity{}).Where("1 = 1").UpdateColumn("state", "active").Error)
		stampLastUsed(t, c, pat.key(patID), c.now())
		stampLastUsed(t, c, mic.key(micID), c.now())

		for _, tc := range []struct {
			name      string
			threshold time.Time // host zone, as core derives it from c.now()
			wantStale int
		}{
			{"threshold after the last use", c.now().Add(time.Minute), 1},
			{"threshold before the last use", c.now().Add(-time.Minute), 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				gotPAT, err := c.storage.CountStalePATs(ctx, tc.threshold)
				require.NoError(t, err)
				require.Equal(t, tc.wantStale, gotPAT, "stale PATs")
				gotMIC, err := c.storage.CountStaleMachineCredentials(ctx, tc.threshold)
				require.NoError(t, err)
				require.Equal(t, tc.wantStale, gotMIC, "stale machine identities")
			})
		}
	})
}

// persistUpdatedCredential hands the counter write c.now() as last_used_at.
func TestWebAuthnCounterLastUsedStoredAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		c, db := d.openLastUsed(t)
		blob, err := json.Marshal(map[string]any{"authenticator": map[string]any{"signCount": 0}})
		require.NoError(t, err)
		require.NoError(t, db.Create(&models.WebAuthnCredential{UserID: 1, CredentialID: []byte("cred-1"),
			Name: "key", CredentialBlob: blob}).Error)

		c.persistUpdatedCredential(context.Background(), 1, ports.WebAuthnVerified{
			ID: []byte("cred-1"), SignCount: 1,
			Credential: map[string]any{"authenticator": map[string]any{"signCount": 1}},
		})

		d.requireStored(t, db, "web_authn_credentials", "last_used_at", utcWritesInstant, "user_id = ?", 1)
	})
}
