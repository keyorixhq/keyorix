package core

// machine_token_cidr_failclosed_test.go — #3396: a machine credential's stored
// allowed_cidrs decodes through rules.DecodePATCIDRs, like a PAT's. An empty column
// (IssueMachineToken's encoding of "no restriction") is unrestricted; a non-empty
// column that names no CIDR fails closed with the sentinel no source IP matches.
// End to end at the middleware: server/http
// TestMachineToken_StoredCIDRsNamingNothing_RefusedAtMiddleware.

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestMachineRestrictionFrom_ColumnNamingNoCIDRFailsClosed(t *testing.T) {
	for _, raw := range []string{"null", "[]", " null ", "[ ]", "\t[]\n", `[null]`, `[""]`, `["  "]`, `["10.0.0.0/8", ""]`, `not json`} {
		t.Run(raw, func(t *testing.T) {
			r := machineRestrictionFrom(&models.MachineIdentityCredential{AllowedCIDRs: raw})
			require.NotNil(t, r, "a non-empty column must never read as unrestricted")
			require.Equal(t, rules.PATCIDRCorrupted, r.AllowedCIDRs)
			for _, ip := range []string{"10.0.0.1", "127.0.0.1", "::1", "192.0.2.4"} {
				require.False(t, IPInCIDRs(ip, r.AllowedCIDRs), "%s must be blocked", ip)
			}
		})
	}
}

func TestMachineRestrictionFrom_EmptyColumnAndRealAllowlistUnchanged(t *testing.T) {
	for _, raw := range []string{"", "  ", "\n"} {
		require.Nil(t, machineRestrictionFrom(&models.MachineIdentityCredential{AllowedCIDRs: raw}), "%q", raw)
	}
	// Whatever IssueMachineToken stores round-trips to the same allowlist.
	enc, err := encodePATCIDRs([]string{"10.0.0.0/8", " 192.0.2.4 "})
	require.NoError(t, err)
	r := machineRestrictionFrom(&models.MachineIdentityCredential{AllowedCIDRs: enc})
	require.NotNil(t, r)
	require.False(t, slices.Equal(r.AllowedCIDRs, rules.PATCIDRCorrupted))
	require.True(t, IPInCIDRs("10.1.2.3", r.AllowedCIDRs))
	require.False(t, IPInCIDRs("172.16.0.1", r.AllowedCIDRs))
}
