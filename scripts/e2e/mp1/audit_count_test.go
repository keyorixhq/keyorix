//go:build e2e

package mp1

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Oracle #5b: exactly one audit entry per acknowledged mutating op ─────────
//
// Companion to TestAuditChainVerifies (which proves the chain is valid and
// gap/fork-free). This proves the COUNT invariant: every acknowledged
// secret.created, written concurrently by different replica processes (so
// their appends contend for the advisory lock), lands EXACTLY ONE
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

// concurrentCreateSecrets creates n secrets at the same time, create i on
// replica i%len(Replicas), so the appends of different replica processes
// contend for the ADR-029 advisory lock. It returns the ids of the
// acknowledged creates and one line per create that was not acknowledged with a
// 2xx and an id (transport error, other status, no id).
func (c *Cluster) concurrentCreateSecrets(prefix string, n int) (ids []int, errs []string) {
	stamp := time.Now().UnixNano()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range n {
		name := fmt.Sprintf("%s-%d-%d", prefix, stamp, i)
		v := strings.TrimPrefix(prefix, "mp1-") + "-" + name
		recordCanary(v)
		wg.Go(func() {
			id, st, err := c.createSecret(c.Replica(i), name, v)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil || (st != http.StatusCreated && st != http.StatusOK):
				errs = append(errs, fmt.Sprintf("create %d on replica %d: st=%d err=%v", i, i%len(c.Replicas), st, err))
			case id == 0:
				errs = append(errs, fmt.Sprintf("create %d on replica %d: acknowledged but no id parsed", i, i%len(c.Replicas)))
			default:
				ids = append(ids, id)
			}
		})
	}
	wg.Wait()
	return ids, errs
}

// TestAuditCountExactlyOne is the live Oracle #5b: fire bursts of concurrent
// secret creates spread over all replica processes, then assert each
// acknowledged create produced exactly one secret.created audit row in the
// shared DB.
func TestAuditCountExactlyOne(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	const burst, rounds = 12, 3
	for round := range rounds {
		ids, errs := c.concurrentCreateSecrets(fmt.Sprintf("mp1-auditcount-r%d", round), burst)
		if len(errs) > 0 {
			t.Fatalf("round %d: %d of %d concurrent creates not acknowledged: %v", round, len(errs), burst, errs)
		}
		counts := c.auditCreatedCounts(t, ids)
		if bad, why := auditCountViolation(counts); bad {
			t.Fatalf("round %d: audit-count oracle: %s (counts=%v) — an acknowledged create did not map to exactly one audit row", round, why, counts)
		}
		t.Logf("round %d: %d concurrent acknowledged creates across %d replicas each produced exactly one secret.created row", round, burst, len(c.Replicas))
	}
}
