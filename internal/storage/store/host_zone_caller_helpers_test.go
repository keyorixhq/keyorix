package store

// UTC-STORE-SCAN-1 item 1. Shared helpers for the per-writer tests that prove a store writer
// normalises the time it is handed to UTC (TestEveryStoreTimeColumnWriteIsUTC,
// internal/core/guards, names the writers). Unlike hook_bypass_time_writers_utc_test.go these tests
// do not re-run under a TZ: the caller's time is built in an explicit non-UTC zone, so the result
// does not depend on the TZ the test binary was started with (they pass the same under TZ=UTC,
// TZ=America/Los_Angeles and TZ=Asia/Kolkata, and fail without the fix under all three).

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// callerZones: west of UTC, +05:30 and a +05:45 zone whose offset has no letter abbreviation.
var callerZones = []string{"America/Los_Angeles", "Asia/Kolkata", "Asia/Kathmandu"}

// eachCallerZone runs f once per backend and caller zone with a "now" in that zone.
func eachCallerZone(t *testing.T, f func(t *testing.T, w ppWorld, at time.Time)) {
	t.Helper()
	for _, backend := range principalPermBackends(t) {
		for _, name := range callerZones {
			loc, err := time.LoadLocation(name)
			if err != nil {
				t.Skipf("zone database has no %s: %v", name, err)
			}
			t.Run(backend+"/"+name, func(t *testing.T) {
				ls, _ := newPrincipalPermStorage(t, backend)
				at := time.Now().In(loc)
				_, off := at.Zone()
				require.NotZero(t, off, "%s must be a non-UTC zone", name)
				f(t, ppWorld{t: t, ls: ls}, at)
			})
		}
	}
}

// requireStoredUTC reads table.column of row id back raw and requires the stored instant to be want
// in UTC: on SQLite the text must carry a zero offset (a host-offset text neither orders against
// the UTC bound nor scans back), on Postgres the timestamp must equal want.
func requireStoredUTC(w ppWorld, table, column string, id uint, want time.Time) {
	w.t.Helper()
	q := "SELECT " + column + " FROM " + table + " WHERE id = ?"
	if w.ls.db.Dialector.Name() != "sqlite" {
		var got sql.NullTime
		require.NoError(w.t, w.ls.db.Raw(q, id).Row().Scan(&got))
		require.True(w.t, got.Valid, "%s.%s not written", table, column)
		require.WithinDuration(w.t, want, got.Time, time.Millisecond, "%s.%s", table, column)
		return
	}
	var raw sql.NullString
	require.NoError(w.t, w.ls.db.Raw(q, id).Row().Scan(&raw))
	require.True(w.t, raw.Valid, "%s.%s not written", table, column)
	stored, ok := parseDBTimestamp(raw.String)
	require.True(w.t, ok, "%s.%s stored as unparseable text %q", table, column, raw.String)
	_, off := stored.Zone()
	require.Zero(w.t, off, "%s.%s stored with the caller's offset: %q (want UTC)", table, column, raw.String)
	require.WithinDuration(w.t, want, stored, time.Millisecond, "%s.%s = %q", table, column, raw.String)
}
