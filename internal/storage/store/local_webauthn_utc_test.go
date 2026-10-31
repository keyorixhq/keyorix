package store

// UTC-TOUCH-1 item 3. SetWebAuthnCredentialCounterState (and so
// AdvanceWebAuthnCredentialCounter) writes last_used_at through
// Updates(map[string]any{...}), which runs no BeforeSave hook and no NowFunc: the
// column holds whatever zone the caller's time carries. Core passes its clock's
// time. On SQLite a non-UTC time is stored as text that neither scans back into
// a *time.Time nor orders against UTC bounds, so the passkey would then fail
// every lookup. The writer normalises, like the Touch* writers
// (touch_last_used_utc_test.go).
//
// The writer only reads the location carried by the time it is handed, so the
// host zones are modelled with time.LoadLocation: no test assigns time.Local
// (it is a process-wide global; see no_time_local_assignment_guard_test.go).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestWebAuthnLastUsedAtStoresUTC(t *testing.T) {
	const blob = `{"authenticator":{"signCount":5}}`
	for _, backend := range principalPermBackends(t) {
		for _, zoneName := range []string{"America/New_York", "Asia/Kolkata"} {
			zone, err := time.LoadLocation(zoneName)
			if err != nil {
				t.Skipf("zone database has no %s: %v", zoneName, err)
			}
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
					require.Equal(t, "UTC", got.LastUsedAt.Location().String(), "last_used_at must scan back as UTC")
					require.NotContains(t, val.String, usedAt.Format("-0700"), "last_used_at stored with the %s offset: %s", zoneName, val.String)
				})
			}
		}
	}
}
