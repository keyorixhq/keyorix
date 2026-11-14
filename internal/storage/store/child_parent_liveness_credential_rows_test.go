package store

// child_parent_liveness_credential_rows_test.go — pins the ledger rows of the three
// credential inserts #2701 closed (CreatePersonalAccessToken, CreateSession,
// RotateSession). Their re-check lives in the shared helper
// requireLiveCredentialOwner, not in a direct lockLiveParent call, so the registry
// still reports the three sites and they stay in docs/child-parent-liveness-exempt.tsv;
// what must not stay is the UNSAFE-OPEN class, which says the race is still open.
//
// What it does not do: prove the race is closed. That is
// TestCredentialInsertsRecheckOwnerLiveness (structure),
// TestCredentialInsertRefusedForUnusableOwner (behaviour, SQLite) and the
// internal/core CrossReplica tests (Postgres).

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChildParentLiveness_CredentialInsertRowsAreClosed(t *testing.T) {
	want := []string{
		"CreatePersonalAccessToken\tPersonalAccessToken\tUser",
		"CreateSession\tSession\tUser",
		"RotateSession\tSession\tUser",
	}
	rows := map[string]childLiveExemptRow{}
	for _, r := range loadChildLiveExempt(t) {
		rows[r.key()] = r
	}
	reported := map[string]bool{}
	for _, v := range childLiveViolations(t, ".") {
		reported[v.Func+"\t"+v.Child+"\t"+v.Parent] = true
	}
	for _, k := range want {
		name := strings.ReplaceAll(k, "\t", " ")
		r, ok := rows[k]
		require.Truef(t, ok, "%s: no exemption row, but the registry still reports this site (the lock is in requireLiveCredentialOwner)", name)
		require.Truef(t, reported[k], "%s: the registry no longer reports this site — the row is stale, delete it", name)
		require.NotContainsf(t, r.Reason, "UNSAFE-OPEN", "%s:%d #2701 is closed (credential-under-suspend-001..006); the row must not say the race is open", childLiveExemptPath, r.Line)
		require.Truef(t, strings.HasPrefix(r.Reason, "SERIALIZED"), "%s:%d reason must be the SERIALIZED class, got %q", childLiveExemptPath, r.Line, r.Reason)
		require.Containsf(t, r.Reason, "requireLiveCredentialOwner", "%s:%d the row must name the helper that holds the lock", childLiveExemptPath, r.Line)
	}
}
