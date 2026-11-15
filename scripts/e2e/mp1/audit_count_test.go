//go:build e2e

package mp1

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Oracle #5b: exactly one audit entry per acknowledged mutating op ─────────
//
// Companion to TestAuditChainVerifies (which proves the chain is valid and
// gap/fork-free). This proves the COUNT invariant: every acknowledged
// secret.created, written across different replica processes, lands EXACTLY ONE
// audit row — never zero (a dropped append) and never two (a double-write under
// the ADR-029 serialize-append advisory lock). core.secrets.go writes the
// secret.created row as the last statement of the same WithTransaction that
// commits the secret (AUDIT-MUTATION-TX-1), so an acknowledged create implies
// exactly one committed audit row.

// auditCountViolation is the pure decision shared with the red proof: a correct
// run has exactly one audit row per acknowledged op id. Any id mapping to a
// count other than 1 (0 = dropped, >=2 = duplicated) is a violation.
func auditCountViolation(perOp map[int]int) (bool, string) {
	for id, n := range perOp {
		if n != 1 {
			return true, fmt.Sprintf("op for resource id %d has %d audit rows, want exactly 1", id, n)
		}
	}
	return false, ""
}

// auditCreatedCounts reads, straight from the shared DB, how many
// secret.created audit rows exist per secret id in ids.
func (c *Cluster) auditCreatedCounts(t *testing.T, ids []int) map[int]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, c.DSN)
	if err != nil {
		t.Fatalf("connect to shared DB for audit counts: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	out := make(map[int]int, len(ids))
	for _, id := range ids {
		out[id] = 0
	}
	rows, err := conn.Query(ctx,
		"SELECT secret_node_id, count(*) FROM audit_events WHERE event_type = 'secret.created' AND secret_node_id = ANY($1) GROUP BY secret_node_id",
		ids)
	if err != nil {
		t.Fatalf("query audit counts: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, n int
		if err := rows.Scan(&id, &n); err != nil {
			t.Fatalf("scan audit count: %v", err)
		}
		out[id] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit counts: %v", err)
	}
	return out
}

// TestAuditCountExactlyOne is the live Oracle #5b: create a burst of secrets
// across all replica processes, then assert each produced exactly one
// secret.created audit row in the shared DB.
func TestAuditCountExactlyOne(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	const burst = 9
	ids := make([]int, 0, burst)
	for i := range burst {
		name := fmt.Sprintf("mp1-auditcount-%d-%d", time.Now().UnixNano(), i)
		v := "auditcount-" + name
		recordCanary(v)
		rep := c.Replica(i % len(c.Replicas))
		id, st, err := c.createSecret(rep, name, v)
		if err != nil || (st != http.StatusCreated && st != http.StatusOK) {
			t.Fatalf("burst create %d: st=%d err=%v", i, st, err)
		}
		if id == 0 {
			t.Fatalf("burst create %d: no id parsed", i)
		}
		ids = append(ids, id)
	}

	// Allow a brief moment for the committed rows to be queryable (they commit
	// with the secret, so this is belt-and-braces, not a staleness window).
	counts := c.auditCreatedCounts(t, ids)
	if bad, why := auditCountViolation(counts); bad {
		t.Fatalf("audit-count oracle: %s (counts=%v) — an acknowledged create did not map to exactly one audit row", why, counts)
	}
	t.Logf("audit-count oracle: %d acknowledged creates across %d replicas each produced exactly one secret.created row", burst, len(c.Replicas))
}
