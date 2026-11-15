//go:build e2e

package mp1

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// ── Oracle #1: uniqueness ────────────────────────────────────────────────────
//
// `projects` carries a PARTIAL unique index `uniq_projects_name_active` on
// name_folded WHERE deleted_at IS NULL (confirmed in the epoch-10 Postgres
// schema snapshot). The HA guarantee: N concurrent creates of the SAME name,
// sprayed across different replica PROCESSES (each with its own connection pool
// — no shared in-process lock can help), must resolve to EXACTLY ONE winner and
// EXACTLY ONE active row. core.CreateProject maps the DB unique violation to
// storage.ErrDuplicateProjectName and returns it as the transaction's error, so
// the losing transaction ROLLBACKs cleanly (the sound Postgres pattern — a
// caught violation returning non-nil, per CLAUDE.md) and the loser gets a 4xx,
// never a second 201.
//
// Two invariants are asserted, both sound regardless of the exact conflict
// status code the HTTP layer picks:
//   - exactly one of the concurrent creates returns 2xx-created, and
//   - the shared DB ends with exactly one active project of that name.
// A 5xx from any create is additionally treated as a server fault under
// concurrent load (racy check-then-act would surface here).

// uniquenessViolation is the pure oracle decision shared by the live oracle and
// the red proof: a correct run has exactly one acknowledged create AND exactly
// one surviving active row. Anything else (two winners, zero winners, a row
// count that disagrees with the ack count) is a violation.
func uniquenessViolation(created, dbRows int) (bool, string) {
	if created != 1 {
		return true, fmt.Sprintf("expected exactly 1 acknowledged create, got %d", created)
	}
	if dbRows != 1 {
		return true, fmt.Sprintf("expected exactly 1 active row, got %d", dbRows)
	}
	return false, ""
}

// createProject POSTs a project create to replica s and returns the HTTP status
// (non-fatal transport errors are returned as err).
func (c *Cluster) createProject(s *harness.Server, name string) (int, error) {
	env, err := c.restTokErr(s, c.AdminToken, http.MethodPost, "/api/v1/projects",
		map[string]any{"name": name})
	if err != nil {
		return 0, err
	}
	return env.StatusCode, nil
}

// countActiveProjects reads the shared DB directly (NOT through a replica, to
// avoid any per-replica cache) and counts active projects whose folded name
// matches a simple-ASCII name. For the ASCII names this harness generates,
// name_folded is the lower-cased name; matching on name = $1 AND deleted_at IS
// NULL is exact and avoids depending on the folding implementation.
func (c *Cluster) countActiveProjects(t *testing.T, name string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, c.DSN)
	if err != nil {
		t.Fatalf("connect to shared DB to count projects: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	var n int
	if err := conn.QueryRow(ctx,
		"SELECT count(*) FROM projects WHERE name = $1 AND deleted_at IS NULL", name).Scan(&n); err != nil {
		t.Fatalf("count active projects %q: %v", name, err)
	}
	return n
}

// concurrentCreate fires one create of name at each replica in reps
// concurrently and returns the per-replica statuses. A 5xx is reported via
// fault (non-empty = a server fault occurred).
func (c *Cluster) concurrentCreate(name string, reps []int) (statuses []int, fault string) {
	statuses = make([]int, len(reps))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, rep := range reps {
		wg.Go(func() {
			st, err := c.createProject(c.Replica(rep), name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				statuses[i] = 0 // transport error: ignore, not a winner
				return
			}
			statuses[i] = st
			if st >= 500 {
				fault = fmt.Sprintf("replica %d create returned 5xx (%d)", rep, st)
			}
		})
	}
	wg.Wait()
	return statuses, fault
}

func count2xx(statuses []int) int {
	n := 0
	for _, st := range statuses {
		if st == http.StatusCreated || st == http.StatusOK {
			n++
		}
	}
	return n
}

// TestUniqueNameExactlyOneWinner is the live Oracle #1: three replicas race to
// create the same project name; exactly one wins and exactly one active row
// survives.
func TestUniqueNameExactlyOneWinner(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)
	n := len(c.Replicas)

	for trial := range 3 {
		name := fmt.Sprintf("mp1-uniq-%d-%d", time.Now().UnixNano(), trial)
		reps := make([]int, n)
		for i := range reps {
			reps[i] = i
		}
		statuses, fault := c.concurrentCreate(name, reps)
		if fault != "" {
			t.Errorf("trial %d: %s (statuses=%v) — server fault under concurrent same-name create", trial, fault, statuses)
		}
		created := count2xx(statuses)
		dbRows := c.countActiveProjects(t, name)
		if bad, why := uniquenessViolation(created, dbRows); bad {
			t.Fatalf("trial %d: uniqueness violated: %s (statuses=%v, dbRows=%d) — concurrent cross-replica creates of %q did not resolve to exactly one",
				trial, why, statuses, dbRows, name)
		}
		t.Logf("trial %d: one winner among %v, %d active row(s) — uniqueness held", trial, statuses, dbRows)
	}
}

// FuzzMP1UniqueCreate fuzzes Oracle #1: the input chooses how many concurrent
// creators (2..3*n) and which replica each targets. Every creator races to
// insert the SAME fresh name; the result must always be exactly one winner and
// exactly one active row.
func FuzzMP1UniqueCreate(f *testing.F) {
	if envNoPG() {
		f.Skip("KEYORIX_TEST_PG_DSN not set — skipping the MP1 multi-process PostgreSQL harness")
	}
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{1, 2})
	f.Add([]byte{2, 1, 0, 1, 2})

	f.Fuzz(func(t *testing.T, data []byte) {
		c := getSharedCluster(t)
		n := len(c.Replicas)
		if len(data) == 0 {
			data = []byte{0, 1}
		}
		// Build the creator list: at least two creators so there is a real race,
		// capped so one input cannot DoS the cluster.
		const maxCreators = 6
		reps := make([]int, 0, maxCreators)
		for _, b := range data {
			if len(reps) >= maxCreators {
				break
			}
			reps = append(reps, int(b)%n)
		}
		for len(reps) < 2 {
			reps = append(reps, len(reps)%n)
		}
		iter := fuzzIter.Add(1)
		name := fmt.Sprintf("mp1-fuzzuniq-%d", iter)
		statuses, fault := c.concurrentCreate(name, reps)
		if fault != "" {
			t.Fatalf("%s (statuses=%v, reps=%v)", fault, statuses, reps)
		}
		created := count2xx(statuses)
		dbRows := c.countActiveProjects(t, name)
		if bad, why := uniquenessViolation(created, dbRows); bad {
			t.Fatalf("uniqueness violated: %s (reps=%v, statuses=%v, dbRows=%d)", why, reps, statuses, dbRows)
		}
	})
}

// envNoPG reports whether the PG DSN is unset (small helper so the fuzz skip
// line stays one statement).
func envNoPG() bool { return os.Getenv("KEYORIX_TEST_PG_DSN") == "" }
