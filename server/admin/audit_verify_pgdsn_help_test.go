package admin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVerifyAudit_PGDSNHelp_WarnsAgainstALiveDatabase pins the operator-facing
// half of INV-AUDITVERIFY-every-row-walked: the offline walk assumes a quiescent
// database, so --pg-dsn must not be pointed at one a running server uses (a purge
// during the walk can read BROKEN). The text is read from the rendered --help, not
// from the flag struct, so it is what an operator sees.
func TestVerifyAudit_PGDSNHelp_WarnsAgainstALiveDatabase(t *testing.T) {
	var out bytes.Buffer
	verifyAuditCmd.SetOut(&out)
	verifyAuditCmd.SetErr(&out)
	t.Cleanup(func() { verifyAuditCmd.SetOut(nil); verifyAuditCmd.SetErr(nil) })
	require.NoError(t, verifyAuditCmd.Help())

	help := strings.Join(strings.Fields(out.String()), " ")
	require.Contains(t, help, "--pg-dsn")
	for _, want := range []string{
		"never at a database a running server uses",
		"a purge running during the walk can make a valid chain read BROKEN",
	} {
		require.Contains(t, help, want)
	}
}
