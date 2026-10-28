// secret_acl_outage_test.go — ERRLOSS-ACL-1 (silent-error-loss audit finding 2):
// a GetSecretACL storage failure must surface as an error on the per-secret
// authorization path, in every locale. Before the fix LocalStorage wrapped every
// GetSecretACL error as i18n ErrorNotFound and aclGrantsPermission matched the text
// "not found": in English a DB outage read as "no ACL grant" (a silent 403 / a
// silently shorter list), in de/es/fr/ru the same outage was an error.
//
// Not t.Parallel(): the localizer is process-global.
package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aclOutageLocales are the locales every case runs under: en (where the text match
// used to read an outage as "no grant") and ru (where it did not).
var aclOutageLocales = []string{"en", "ru"}

// withACLOutageLocale switches the process-global localizer to lang for the test.
func withACLOutageLocale(t *testing.T, lang string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	loc := i18n.GetLocalizer()
	loc.SetLanguage(lang)
	t.Cleanup(func() { loc.SetLanguage("en") })
	if lang == "ru" {
		// Floor: an untranslated ErrorNotFound would make the ru run an en run.
		require.NotContains(t, i18n.T("ErrorNotFound", nil), "not found",
			"the ru locale must not render ErrorNotFound in English, or this test proves nothing")
	}
}

// preFixOutageErr is the error a DB outage produced from GetSecretACL before the
// fix: the driver error wrapped under the localized ErrorNotFound text.
func preFixOutageErr(driverErr error) error {
	return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), driverErr)
}

// TestSecretACLOutage_FaultInjectedDeniesWithError injects a GetSecretACL failure
// through the faultstorage double. User 55 is a project member with no role and no
// ACL row, so "no grant" would be a plain denial; the outage must instead be an
// error from HasSecretACL, AuthorizeSecret (the HTTP/gRPC gate's decision) and
// CheckSecretPermission (the in-core per-secret check), identically in en and ru.
func TestSecretACLOutage_FaultInjectedDeniesWithError(t *testing.T) {
	for _, lang := range aclOutageLocales {
		t.Run(lang, func(t *testing.T) {
			withACLOutageLocale(t, lang)
			ctx := context.Background()
			c, db := newACLCore(t)
			sid := mkACLSecret(t, db, "acl-outage-"+lang)
			driverErr := errors.New("driver: bad connection")

			arm := func() (*KeyorixCore, *faultstorage.FaultyStorage) {
				faulty := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
					Method: "GetSecretACL", NthCall: 1, Kind: faultstorage.KindError, Err: preFixOutageErr(driverErr),
				})
				return newACLCoreWithStorage(c, faulty), faulty
			}

			c2, faulty := arm()
			has, err := c2.HasSecretACL(ctx, 55, sid, "secrets.read")
			require.True(t, faulty.Fired(), "the GetSecretACL fault must have fired, or this case proves nothing")
			require.Error(t, err, "a GetSecretACL outage must not read as 'no ACL grant'")
			assert.ErrorIs(t, err, driverErr)
			assert.False(t, has)

			c2, faulty = arm()
			ok, err := c2.AuthorizeSecret(ctx, 55, sid, "secrets.read")
			require.True(t, faulty.Fired())
			require.Error(t, err, "the gate decision must fail with the outage, not deny as if no grant existed")
			assert.ErrorIs(t, err, driverErr)
			assert.False(t, ok, "an outage must never grant")

			c2, faulty = arm()
			_, err = c2.CheckSecretPermission(ctx, sid, 55, PermissionRead)
			require.True(t, faulty.Fired())
			require.Error(t, err)
			assert.ErrorIs(t, err, driverErr, "the outage must propagate, not become a permission denial")
			assert.NotContains(t, err.Error(), "insufficient permissions")
		})
	}
}

// TestSecretACLOutage_RealStoreFailureDeniesWithError drives the real LocalStorage
// (no double): the secret_acls table is gone, so only GetSecretACL fails, with a real
// driver error. Before the fix that read as "no grant" in en.
func TestSecretACLOutage_RealStoreFailureDeniesWithError(t *testing.T) {
	for _, lang := range aclOutageLocales {
		t.Run(lang, func(t *testing.T) {
			withACLOutageLocale(t, lang)
			ctx := context.Background()
			c, db := newACLCore(t)
			sid := mkACLSecret(t, db, "acl-dropped-"+lang)
			require.NoError(t, db.Exec("DROP TABLE secret_acls").Error)

			ok, err := c.AuthorizeSecret(ctx, 55, sid, "secrets.read")
			require.Error(t, err, "a failed ACL read must not read as 'no ACL grant'")
			assert.False(t, ok, "an outage must never grant")
		})
	}
}

// TestSecretACLOutage_NoRowIsStillNoGrant is the control: with storage working and
// no ACL row, the answer is a plain "no grant" (no error) in every locale.
func TestSecretACLOutage_NoRowIsStillNoGrant(t *testing.T) {
	for _, lang := range aclOutageLocales {
		t.Run(lang, func(t *testing.T) {
			withACLOutageLocale(t, lang)
			ctx := context.Background()
			c, db := newACLCore(t)
			sid := mkACLSecret(t, db, "acl-norow-"+lang)

			has, err := c.HasSecretACL(ctx, 55, sid, "secrets.read")
			require.NoError(t, err)
			assert.False(t, has)
			ok, err := c.AuthorizeSecret(ctx, 55, sid, "secrets.read")
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}
