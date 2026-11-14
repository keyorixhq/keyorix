//go:build e2e

package mp1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// jsonUnmarshal is a thin alias so the op helpers read cleanly.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// TestMain builds once, runs the suite, then kills every server process this
// package started and drops every mp1_ database it created, before removing
// the shared build dir. The cluster is started lazily by the first test/fuzz
// iteration that needs it (startSharedOnce) and lives until here — NOT tied to
// any one iteration's t.Cleanup, which would tear the servers down after the
// first fuzz input.
func TestMain(m *testing.M) {
	code := m.Run()
	runTeardowns()
	harness.CleanupBinaries()
	os.Exit(code)
}

// requirePG skips (never fails) when no Postgres DSN is configured — the same
// contract every pg-gated test in this repo uses.
func requirePG(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping the MP1 multi-process PostgreSQL harness")
	}
}

// ── shared cluster (started once, reused by the fuzz loop) ──────────────────

var (
	sharedOnce    sync.Once
	sharedCluster *Cluster
	sharedErr     string
)

// sharedReplicaCount is how many real server processes the fuzz loop drives.
// Three gives a genuine three-way race (A/B/C) while staying within the
// ~150 MB/process, <3 GB-total budget.
const sharedReplicaCount = 3

func getSharedCluster(t *testing.T) *Cluster {
	t.Helper()
	sharedOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				sharedErr = fmt.Sprintf("panic starting shared cluster: %v", r)
			}
		}()
		sharedCluster = StartCluster(t, sharedReplicaCount, "")
	})
	if sharedCluster == nil {
		t.Fatalf("shared cluster unavailable: %s", sharedErr)
	}
	return sharedCluster
}

// ── secret ops over REST ────────────────────────────────────────────────────

func (c *Cluster) createSecret(s *harness.Server, name, value string) (id, status int, err error) {
	env, err := c.restTokErr(s, c.AdminToken, http.MethodPost, "/api/v1/secrets",
		map[string]any{"name": name, "value": value, "project_id": c.ProjID, "environment_id": c.EnvID, "type": "password"})
	if err != nil {
		return 0, 0, err
	}
	if env.StatusCode != http.StatusCreated && env.StatusCode != http.StatusOK {
		return 0, env.StatusCode, nil
	}
	var d struct {
		ID     int `json:"id"`
		Secret struct {
			ID int `json:"id"`
		} `json:"secret"`
	}
	if jerr := jsonUnmarshal(env.Data, &d); jerr != nil {
		return 0, env.StatusCode, jerr
	}
	if d.ID != 0 {
		return d.ID, env.StatusCode, nil
	}
	return d.Secret.ID, env.StatusCode, nil
}

func (c *Cluster) updateSecret(s *harness.Server, id int, value string) (int, error) {
	env, err := c.restTokErr(s, c.AdminToken, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id),
		map[string]any{"value": value})
	if err != nil {
		return 0, err
	}
	return env.StatusCode, nil
}

func (c *Cluster) rotateSecret(s *harness.Server, id int, value string) (int, error) {
	env, err := c.restTokErr(s, c.AdminToken, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id),
		map[string]any{"new_value": value})
	if err != nil {
		return 0, err
	}
	return env.StatusCode, nil
}

func (c *Cluster) readSecretValue(s *harness.Server, id int) (value string, status int, err error) {
	env, err := c.restTokErr(s, c.AdminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
	if err != nil {
		return "", 0, err
	}
	if env.StatusCode != http.StatusOK {
		return "", env.StatusCode, nil
	}
	var d struct {
		Value  string `json:"value"`
		Secret struct {
			Value string `json:"value"`
		} `json:"secret"`
	}
	if jerr := jsonUnmarshal(env.Data, &d); jerr != nil {
		return "", env.StatusCode, jerr
	}
	if d.Value != "" {
		return d.Value, env.StatusCode, nil
	}
	return d.Secret.Value, env.StatusCode, nil
}

// ── canary bookkeeping ──────────────────────────────────────────────────────
//
// Every secret value the harness ever writes is a canary: it must never appear
// in any replica's log. The set is scanned in TestZZCanaryNoSecretInLogs (which
// sorts after the fuzz corpus run alphabetically) and in the dedicated canary
// oracle test.

var (
	canaryMu     sync.Mutex
	canaryValues = map[string]struct{}{}
)

func recordCanary(values ...string) {
	canaryMu.Lock()
	for _, v := range values {
		if v != "" {
			canaryValues[v] = struct{}{}
		}
	}
	canaryMu.Unlock()
}

func canarySnapshot() []string {
	canaryMu.Lock()
	defer canaryMu.Unlock()
	out := make([]string, 0, len(canaryValues))
	for v := range canaryValues {
		out = append(out, v)
	}
	return out
}

// maxConvergeNanos records the longest cross-replica convergence delay the fuzz
// loop observed for a secret value (post-return visibility window, measured).
var maxConvergeNanos int64

func recordConverge(d time.Duration) {
	for {
		cur := atomic.LoadInt64(&maxConvergeNanos)
		if int64(d) <= cur || atomic.CompareAndSwapInt64(&maxConvergeNanos, cur, int64(d)) {
			return
		}
	}
}

// fuzzIter gives each iteration a process-unique id so its secret name never
// collides with another iteration's in the shared database.
var fuzzIter int64

// FuzzMP1MultiProc drives a fuzz-chosen interleaving of concurrent secret
// writes across the real replica processes and checks two oracles per
// iteration:
//
//   - CONVERGENCE / post-return visibility: after every write has returned, a
//     read of the secret on EVERY replica yields the same value (within a
//     bounded convergence window — secret VALUES are DB-authoritative, not
//     cached cross-replica, so the expected window is sub-second; the measured
//     max is reported).
//   - SERIAL EQUIVALENCE (necessary condition): the converged final value is
//     one that SOME write which returned success actually set — never a torn,
//     phantom, or failed-write value. For a single register this is the
//     checkable necessary condition of "the state equals some serial order of
//     the successful operations".
//
// It also fails on any 5xx from a write or read (a concurrent-access server
// fault). The fuzz input chooses: the replica that receives the create, and a
// sequence of (replica, update|rotate) write ops run concurrently.
func FuzzMP1MultiProc(f *testing.F) {
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		f.Skip("KEYORIX_TEST_PG_DSN not set — skipping the MP1 multi-process PostgreSQL harness")
	}

	// Meaningful seeds: single-replica baseline; two replicas racing one
	// update each; three replicas each writing; a rotate mixed with updates;
	// a longer concurrent burst.
	f.Add([]byte{0})
	f.Add([]byte{0, 1, 0, 2, 0})
	f.Add([]byte{0, 0, 0, 1, 0, 2, 0})
	f.Add([]byte{1, 0, 1, 1, 0, 2, 1})
	f.Add([]byte{2, 0, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		c := getSharedCluster(t)
		n := len(c.Replicas)
		if len(data) == 0 {
			data = []byte{0}
		}
		iter := atomic.AddInt64(&fuzzIter, 1)
		name := fmt.Sprintf("mp1-s-%d", iter)
		v0 := fmt.Sprintf("v-%d-0", iter)
		recordCanary(v0)

		createRep := int(data[0]) % n
		id, status, err := c.createSecret(c.Replica(createRep), name, v0)
		if err != nil {
			t.Skipf("create transport error (ignored, not an oracle failure): %v", err)
		}
		if status >= 500 {
			t.Fatalf("create returned 5xx (%d) on replica %d — server fault under concurrent load", status, createRep)
		}
		if status != http.StatusCreated && status != http.StatusOK {
			// A non-5xx rejection (e.g. policy) is not a race bug; nothing to check.
			t.Skipf("create not accepted (HTTP %d); skipping", status)
		}
		if id == 0 {
			t.Skipf("create accepted but no id parsed; skipping")
		}

		// Decode the remaining bytes into concurrent write ops.
		type writeOp struct {
			rep    int
			rotate bool
			value  string
		}
		var ops []writeOp
		const maxOps = 10
		body := data[1:]
		for i := 0; i+1 < len(body) && len(ops) < maxOps; i += 2 {
			ops = append(ops, writeOp{
				rep:    int(body[i]) % n,
				rotate: body[i+1]%2 == 1,
				value:  fmt.Sprintf("v-%d-%d", iter, len(ops)+1),
			})
		}
		if len(ops) == 0 {
			// At least one write so there is a race to observe.
			ops = append(ops, writeOp{rep: 1 % n, value: fmt.Sprintf("v-%d-1", iter)})
		}

		// success set: v0 plus every write whose call returned 2xx.
		var mu sync.Mutex
		success := map[string]struct{}{v0: {}}
		var fault string

		var wg sync.WaitGroup
		for _, op := range ops {
			op := op
			recordCanary(op.value)
			wg.Add(1)
			go func() {
				defer wg.Done()
				var st int
				var e error
				if op.rotate {
					st, e = c.rotateSecret(c.Replica(op.rep), id, op.value)
				} else {
					st, e = c.updateSecret(c.Replica(op.rep), id, op.value)
				}
				mu.Lock()
				defer mu.Unlock()
				if e != nil {
					return // transport error on one goroutine: ignore
				}
				if st >= 500 {
					fault = fmt.Sprintf("write (rotate=%v) on replica %d returned 5xx (%d)", op.rotate, op.rep, st)
					return
				}
				if st == http.StatusOK || st == http.StatusCreated {
					success[op.value] = struct{}{}
				}
			}()
		}
		wg.Wait()
		if fault != "" {
			t.Fatalf("concurrent write fault: %s", fault)
		}

		// CONVERGENCE: read on every replica; retry up to the window to allow
		// any (unexpected) eventual consistency, recording how long it took.
		const convWindow = 3 * time.Second
		deadline := time.Now().Add(convWindow)
		start := time.Now()
		var final string
		for {
			vals := make([]string, 0, n)
			converged := true
			for i := 0; i < n; i++ {
				v, st, rerr := c.readSecretValue(c.Replica(i), id)
				if rerr != nil {
					converged = false
					break
				}
				if st >= 500 {
					t.Fatalf("read returned 5xx (%d) on replica %d", st, i)
				}
				if st != http.StatusOK {
					converged = false
					break
				}
				vals = append(vals, v)
			}
			if converged && len(vals) == n && allEqual(vals) {
				final = vals[0]
				recordConverge(time.Since(start))
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("replicas did not converge within %s after all writes returned: reads=%v (successful writes=%v) — cross-replica divergence",
					convWindow, vals, keys(success))
			}
			time.Sleep(50 * time.Millisecond)
		}

		// SERIAL EQUIVALENCE (necessary condition): the surviving value must be
		// one that some successful write set.
		if serialEquivViolation(final, success) {
			t.Fatalf("final converged value %q was set by NO successful write (successful writes=%v) — serial-equivalence violation: a torn or phantom value survived",
				final, keys(success))
		}
	})
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
