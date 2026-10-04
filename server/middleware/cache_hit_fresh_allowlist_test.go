// cache_hit_fresh_allowlist_test.go — INV-MW-06 (#2519).
//
// serveAuthCacheHit enforces the network allowlist on every request, cache hit
// included, and must evaluate it against `effective` — the UserContext freshly
// cloned with the restriction just re-read from storage — never against the
// stale `entry.userCtx` snapshot captured when the entry was cached. And the
// refresh must be a clone: the cached entry itself is shared by every
// concurrent request for that token and must not be mutated in place.
//
// TestAuthentication_PATNetworkAllowlist_RefreshesOnCacheHit and
// TestAuthentication_MachineTokenCIDR_RefreshesOnCacheHit cover the "narrowed"
// direction incidentally. This file isolates the property across every
// direction in which stale and fresh disagree — narrowed, restriction added to
// a previously unrestricted token, restriction removed — for both credential
// kinds that carry an allowlist (sessions have none), and asserts the cached
// snapshot is left untouched.
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type allowlistProbe struct {
	remoteAddr string
	want       int
}

// snapshotRestrictions returns the cached entry's restriction pointers, so a
// test can assert a cache hit did not overwrite them in place.
func snapshotRestrictions(t *testing.T, raw string) (*core.PATRestriction, *core.MachineTokenRestriction) {
	t.Helper()
	entry, found := cacheGet(tokenKey(raw))
	require.True(t, found)
	require.NotNil(t, entry.userCtx)
	return entry.userCtx.PATRestriction, entry.userCtx.MachineTokenRestriction
}

func TestCacheHit_NetworkAllowlist_EvaluatedAgainstFreshRestriction(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	hash := func(raw string) string {
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:])
	}

	cases := []struct {
		name string
		// raw is a fakeValidator token: its slow-path (cached) restriction is
		// fixed by fakeValidator — kx_pat_cidrtoken → 10.0.0.0/8,
		// kx_pat_validtoken / kx_machine_validtoken → none.
		raw        string
		machine    bool
		storedCIDR string // AllowedCIDRs written to storage after caching ("" = unrestricted)
		populateIP string // first, cache-populating request
		probes     []allowlistProbe
	}{
		{
			name: "PAT narrowed: stale allows, fresh denies", raw: "kx_pat_cidrtoken",
			storedCIDR: `["192.0.2.0/24"]`, populateIP: "10.1.2.3:5555",
			probes: []allowlistProbe{{"10.1.2.3:5555", http.StatusForbidden}, {"192.0.2.7:5555", http.StatusOK}},
		},
		{
			name: "PAT restriction added to unrestricted token", raw: "kx_pat_validtoken",
			storedCIDR: `["192.0.2.0/24"]`, populateIP: "10.1.2.3:5555",
			probes: []allowlistProbe{{"10.1.2.3:5555", http.StatusForbidden}, {"192.0.2.7:5555", http.StatusOK}},
		},
		{
			name: "PAT restriction removed: stale denies, fresh allows", raw: "kx_pat_cidrtoken",
			storedCIDR: "", populateIP: "10.1.2.3:5555",
			probes: []allowlistProbe{{"203.0.113.9:5555", http.StatusOK}, {"10.1.2.3:5555", http.StatusOK}},
		},
		{
			name: "machine token restriction added to unrestricted token", raw: "kx_machine_validtoken", machine: true,
			storedCIDR: `["192.0.2.0/24"]`, populateIP: "10.1.2.3:5555",
			probes: []allowlistProbe{{"10.1.2.3:5555", http.StatusForbidden}, {"192.0.2.7:5555", http.StatusOK}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetTokenCacheG18(tc.raw)
			t.Cleanup(func() { resetTokenCacheG18(tc.raw) })

			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			require.NoError(t, err)
			var update func()
			if tc.machine {
				require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))
				require.NoError(t, db.Create(&models.MachineIdentity{ID: 9, Name: "ci-bot", State: "active"}).Error)
				cred := &models.MachineIdentityCredential{ID: 1, MachineIdentityID: 9, Name: "ci", TokenHash: hash(tc.raw)}
				require.NoError(t, db.Create(cred).Error)
				update = func() {
					cred.AllowedCIDRs = tc.storedCIDR
					require.NoError(t, db.Save(cred).Error)
				}
			} else {
				require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
				require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)
				pat := &models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hash(tc.raw)}
				require.NoError(t, db.Create(pat).Error)
				update = func() {
					pat.AllowedCIDRs = tc.storedCIDR
					require.NoError(t, db.Save(pat).Error)
				}
			}

			coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
			handler := authenticationWithValidator(fakeValidator{}, coreService)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

			require.Equal(t, http.StatusOK, serveFrom(handler, tc.raw, tc.populateIP), "first request caches via the slow path")
			stalePAT, staleMachine := snapshotRestrictions(t, tc.raw)

			update()

			for _, p := range tc.probes {
				require.Equal(t, p.want, serveFrom(handler, tc.raw, p.remoteAddr),
					"cache-hit request from %s must be evaluated against the freshly re-read allowlist %q, not the cached snapshot", p.remoteAddr, tc.storedCIDR)
			}

			gotPAT, gotMachine := snapshotRestrictions(t, tc.raw)
			require.Same(t, stalePAT, gotPAT, "the cache hit must refresh on a clone, never overwrite the shared cached PATRestriction in place")
			require.Same(t, staleMachine, gotMachine, "the cache hit must refresh on a clone, never overwrite the shared cached MachineTokenRestriction in place")
		})
	}
}
