package http

// machine_token_cidr_failclosed_test.go — #3396 end to end: a machine credential whose
// stored allowed_cidrs is non-empty but names no CIDR (`null`, `[]`, a blank entry) is
// refused at the auth middleware from every network. IssueMachineToken stores "" for
// "no restriction", so such a column is a corrupted or hand-edited row; before the fix
// machineRestrictionFrom read it as "no restriction" and the IP pin was dropped. The
// PAT path already failed closed (rules.DecodePATCIDRs).

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestMachineToken_StoredCIDRsNamingNothing_RefusedAtMiddleware(t *testing.T) {
	cgBackends(t, func(t *testing.T, backend string) {
		for _, raw := range []string{"null", "[]", `[""]`, `["  "]`} {
			t.Run(raw, func(t *testing.T) {
				w := newSVWorld(t, backend, 2)
				sec, _ := w.newSecret(t, nil)
				url := fmt.Sprintf("/api/v1/secrets/%d", sec.ID)
				token := w.tokens["machine"]
				var cred models.MachineIdentityCredential
				require.NoError(t, w.a.db.Where("token_hash = ?", cgSHA256Hex(token)).First(&cred).Error)
				require.Empty(t, cred.AllowedCIDRs, "fixture: an unrestricted token stores an empty column")

				// Fill B's auth cache while the column is valid (unrestricted).
				require.Equal(t, "200", cgGet(w.b, token, url))

				require.NoError(t, w.a.db.Model(&models.MachineIdentityCredential{}).
					Where("id = ?", cred.ID).Update("AllowedCIDRs", raw).Error)

				// A: first sight of the token (validation path). B: the cache hit's
				// live re-check (CurrentMachineTokenRestriction).
				for name, r := range map[string]*svReplica{"validation": w.a, "cache-hit": w.b} {
					got := cgGet(r, token, url)
					require.Contains(t, got, "403", "%s: allowed_cidrs %q must block every source IP", name, raw)
					require.Contains(t, got, "not permitted from this network", name)
				}
			})
		}
	})
}
