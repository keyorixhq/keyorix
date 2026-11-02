package store

// The raw credential lookup scans its three time columns through sql.NullTime
// (assignCredentialTimes). Golden check: the result is reflect.DeepEqual to the
// previous scan straight into the model's *time.Time / time.Time fields, for
// every NULL/non-NULL combination, on SQLite and (KEYORIX_TEST_PG_DSN) Postgres.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	legacysqlite "gorm.io/driver/sqlite"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// directTimeCredentialScan is the scan as it was before assignCredentialTimes:
// times straight into the model's fields.
func directTimeCredentialScan(ctx context.Context, t *testing.T, ls *LocalStorage, hash string) (*models.MachineIdentityCredential, string) {
	t.Helper()
	sqlDB, err := ls.db.DB()
	require.NoError(t, err)
	var c models.MachineIdentityCredential
	var identityState string
	require.NoError(t, sqlDB.QueryRowContext(ctx, rebindForDialect(ls.db.Dialector.Name(), credentialLookupRawQuery), hash).Scan(
		&c.ID, &c.MachineIdentityID, &c.Name, &c.TokenHash, &c.TokenPrefix,
		&c.AllowedCIDRs, &c.LastUsedAt, &c.ExpiresAt, &c.Revoked, &c.CreatedAt,
		&c.Classification, &identityState,
	))
	return &c, identityState
}

// The sqlite leg stays on gorm.io/driver/sqlite on purpose (SQLITE-FIDELITY-1
// finding): on the production dialect (modernc) a timestamp carrying a fixed
// non-UTC zone (the +02:00 fixture below) is stored in a form that scans back as
// a string, "unsupported Scan, storing driver.Value type string into type
// *time.Time", for sql.NullTime as well as time.Time. The fixture is not changed
// to UTC because that would drop the zone coverage.
//
// Can production still write such a value to the two credential tables
// (personal_access_tokens, machine_identity_credentials) that this lookup and
// the PAT reader scan? No, since SQLITE-UTC-NOWFUNC-1. Every writer of
// created_at / expires_at / last_used_at on them:
//   - created_at: core/pat.go and core/machine_token.go assign c.now().UTC()
//     (the only two creators; CreatePersonalAccessToken and
//     CreateMachineIdentityCredential have no other non-test caller); a zero
//     created_at is stamped by GORM's NowFunc, which gormConfig now returns in
//     UTC (internal/storage/nowfunc_utc_test.go).
//   - expires_at: only set on the model at create, and both models'
//     BeforeSave hooks convert it to UTC, so a client RFC3339 offset
//     (server/http sqlite_offset_time_blackbox_test.go) is stored as UTC.
//     No Updates / UpdateColumn writes expires_at on either table.
//   - last_used_at: only TouchPersonalAccessToken and
//     TouchMachineIdentityCredential (both UTC since this change,
//     touch_last_used_utc_test.go), reached from the core last-used coalescer.
//   - restore: backupfmt decodes every archived row through
//     normalizeTimesToUTC (row_codec.go), including a v0.95.x archive with
//     "+01:00" offsets.
//
// What this does not cover: rows already stored zoned by an earlier release stay
// unscannable until rewritten, and a future writer that is not on this list.
func TestCredentialLookupRaw_TimesMatchDirectScan(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorageOn(t, backend, legacysqlite.Open)
			require.NoError(t, ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			mid := w.machine(w.project())
			at := time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.FixedZone("x", 2*3600))
			for i, shape := range []struct{ lastUsed, expires bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
				hash := w.name("times-hash")
				cred := &models.MachineIdentityCredential{
					MachineIdentityID: mid, Name: hash, TokenHash: hash, TokenPrefix: "kx_",
					AllowedCIDRs: strings.Repeat(`["10.0.0.0/8"]`, i%2), Revoked: i == 3,
					CreatedAt: at.Add(time.Duration(i) * time.Hour), Classification: "internal",
				}
				if shape.lastUsed {
					lu := at.Add(time.Minute)
					cred.LastUsedAt = &lu
				}
				if shape.expires {
					ex := at.Add(48 * time.Hour)
					cred.ExpiresAt = &ex
				}
				require.NoError(t, ls.db.Create(cred).Error)

				want, wantState := directTimeCredentialScan(ctx, t, ls, hash)
				got, gotState, handled, err := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, hash)
				require.True(t, handled)
				require.NoError(t, err)
				require.Equal(t, wantState, gotState)
				require.Equal(t, want, got, "shape %+v", shape)
				require.Equal(t, shape.lastUsed, got.LastUsedAt != nil)
				require.Equal(t, shape.expires, got.ExpiresAt != nil)
			}
		})
	}
}

// A NULL created_at stays an error, as it was when scanned into a time.Time.
func TestAssignCredentialTimes_NullCreatedAtIsAnError(t *testing.T) {
	var c models.MachineIdentityCredential
	require.ErrorIs(t, assignCredentialTimes(&c, sql.NullTime{}, sql.NullTime{}, sql.NullTime{}), errCredentialCreatedAtNull)
	now := time.Now()
	require.NoError(t, assignCredentialTimes(&c, sql.NullTime{}, sql.NullTime{Time: now, Valid: true}, sql.NullTime{Time: now, Valid: true}))
	require.Nil(t, c.LastUsedAt)
	require.Equal(t, now, *c.ExpiresAt)
	require.Equal(t, now, c.CreatedAt)
}
