package store

// UTC-TOUCH-1: storage-level regression guard for the UTC-WRITES-1 fix (#3881).
// SetWebAuthnCredentialCounterState (and so AdvanceWebAuthnCredentialCounter)
// writes last_used_at through Updates(map[string]any{...}), which runs no
// BeforeSave hook and no NowFunc: the column holds whatever zone the time it is
// handed carries. Core passes its clock's time. On SQLite a named-zone time is
// stored as text that keeps its offset ("2026-11-01T10:25:34.176348+05:30",
// observed before #3881). The row still scans back, but in that zone (EDT, IST)
// rather than UTC, and as text its offset form does not order lexically against
// "...Z" UTC text in a range comparison. #3881 made the writer normalise with
// .UTC(), like the Touch* writers (touch_last_used_utc_test.go);
// main's TestWebAuthnCounterLastUsedStoredAsUTC covers it only through core's
// persistUpdatedCredential. This test pins both storage entry points directly,
// on SQLite and Postgres. It is a guard, not a fix proof: it passes on main.
//
// The writer only reads the location carried by the time it is handed, so the
// host zones are modelled with time.LoadLocation: no test assigns time.Local
// (it is a process-wide global; see no_time_local_assignment_guard_test.go).
// time/tzdata is embedded so the zones always load and the guard never skips on
// a runner image without a zone database.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestWebAuthnLastUsedAtStoresUTC(t *testing.T) {
	const blob = `{"authenticator":{"signCount":5}}`
	for _, backend := range principalPermBackends(t) {
		for _, zoneName := range []string{"America/New_York", "Asia/Kolkata"} {
			zone, err := time.LoadLocation(zoneName)
			require.NoError(t, err, "load %s from the embedded zone database", zoneName)
			for _, writer := range []string{"SetWebAuthnCredentialCounterState", "AdvanceWebAuthnCredentialCounter"} {
				t.Run(backend+"/"+zoneName+"/"+writer, func(t *testing.T) {
					ls, _ := newPrincipalPermStorage(t, backend)
					require.NoError(t, ls.db.AutoMigrate(&models.WebAuthnCredential{}))
					w := ppWorld{t: t, ls: ls}
					ctx := context.Background()

					userID := w.user()
					credID := []byte(w.name("cred"))
					require.NoError(t, ls.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
						UserID: userID, CredentialID: credID, Name: "key", CredentialBlob: []byte(blob),
					}))

					usedAt := time.Now().In(zone)
					newBlob := []byte(`{"authenticator":{"signCount":6}}`)
					switch writer {
					case "SetWebAuthnCredentialCounterState":
						row, err := ls.LockWebAuthnCredentialForUpdate(ctx, credID, userID)
						require.NoError(t, err)
						matched, err := ls.SetWebAuthnCredentialCounterState(ctx, row.ID, newBlob, usedAt)
						require.NoError(t, err)
						require.True(t, matched)
					case "AdvanceWebAuthnCredentialCounter":
						advanced, err := ls.AdvanceWebAuthnCredentialCounter(ctx, credID, userID, newBlob, 6, usedAt)
						require.NoError(t, err)
						require.True(t, advanced)
					}

					got, err := ls.LockWebAuthnCredentialForUpdate(ctx, credID, userID)
					require.NoError(t, err, "a credential with last_used_at set in %s must scan back", zoneName)
					require.NotNil(t, got.LastUsedAt)
					require.WithinDuration(t, usedAt, *got.LastUsedAt, time.Millisecond)

					if backend != "sqlite" {
						return
					}
					var val sql.NullString
					require.NoError(t, ls.db.Raw("SELECT last_used_at FROM web_authn_credentials WHERE id = ?", got.ID).Row().Scan(&val))
					require.True(t, strings.HasSuffix(val.String, "Z"), "last_used_at must be stored as UTC text, got %q (%s)", val.String, zoneName)
					require.Equal(t, "UTC", got.LastUsedAt.Location().String(), "last_used_at must scan back as UTC")
				})
			}
		}
	}
}
