package guards

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPendingExemptionRows_ReadsFragments: the "pending: #NNNN" scan of
// TestExemptLedgers_PendingRowsNotMerged sees a row that lives only in
// docs/<name>.d/, as it must once scripts/ledgers/migrate-to-fragments.sh has
// emptied the flat ledger. Red on a flat-only reader (no rows), green on the
// dual reader.
func TestPendingExemptionRows_ReadsFragments(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("check-then-act-lock-exempt.tsv", "# header only: every row was migrated\n")
	write("check-then-act-lock-exempt.d/F1.tsv", "F1\tUNSAFE-OPEN\tpending: #4242 fix in flight\n")
	write("check-then-act-lock-exempt.d/F2.tsv", "F2\tSAFE\tno pending mention\n")

	rows := pendingExemptionRows(t, dir)
	require.Equal(t, []pendingExemption{{where: "docs/check-then-act-lock-exempt.d/F1.tsv:1", pr: "4242"}}, rows)

	// A flat row is still seen next to the fragment.
	write("check-then-act-lock-exempt.tsv", "F0\tUNSAFE-OPEN\tpending: #4141\n")
	rows = pendingExemptionRows(t, dir)
	require.Len(t, rows, 2)
	require.Equal(t, "4141", rows[0].pr)
	require.Equal(t, "docs/check-then-act-lock-exempt.tsv:1", rows[0].where)
}
