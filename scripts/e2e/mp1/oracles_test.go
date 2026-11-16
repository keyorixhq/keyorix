//go:build e2e

package mp1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// validTokenTTL mirrors server/middleware/auth.go's positive auth-cache TTL
// (30s): the documented window within which a credential revoked on one
// replica must stop authenticating on every other replica. A replica that
// positively cached the credential may keep accepting it up to this long —
// but never past it.
const validTokenTTL = 30 * time.Second

// ── Oracle: post-return visibility (secret value) ───────────────────────────
//
// Secret VALUES are DB-authoritative; ADR-039 lists only the 30s token/session
// caches and the negative-auth cache as per-replica stale-tolerant state —
// NOT secret values. So a value written (and returned success) on replica A
// must be readable on every OTHER replica effectively immediately. This test
// measures the actual window per replica and fails if it exceeds a generous
// 2s bound (far below the 30s auth window, which does not apply to values).
func TestVisibilityWindow(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)
	n := len(c.Replicas)

	name := fmt.Sprintf("mp1-vis-%d", time.Now().UnixNano())
	v := "visible-" + name
	recordCanary(v)
	id, status, err := c.createSecret(c.Replica(0), name, v)
	if err != nil || (status != http.StatusCreated && status != http.StatusOK) {
		t.Fatalf("create on replica 0: status=%d err=%v", status, err)
	}

	const bound = 2 * time.Second
	for i := 1; i < n; i++ {
		start := time.Now()
		deadline := start.Add(bound)
		var seen bool
		var last string
		for time.Now().Before(deadline) {
			got, st, rerr := c.readSecretValue(c.Replica(i), id)
			last = got
			if rerr == nil && st == http.StatusOK && got == v {
				seen = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !seen {
			t.Fatalf("replica %d never saw value written on replica 0 within %s (last read %q) — value not DB-authoritative across replicas", i, bound, last)
		}
		t.Logf("replica %d saw the cross-replica value after %s (bound %s)", i, time.Since(start).Round(time.Millisecond), bound)
	}

	// Measure an update's propagation too (the create path and the update path
	// take different code).
	v2 := v + "-upd"
	recordCanary(v2)
	start := time.Now()
	if st, uerr := c.updateSecret(c.Replica(0), id, v2); uerr != nil || st != http.StatusOK {
		t.Fatalf("update on replica 0: status=%d err=%v", st, uerr)
	}
	for i := 1; i < n; i++ {
		deadline := time.Now().Add(bound)
		var seen bool
		for time.Now().Before(deadline) {
			got, st, rerr := c.readSecretValue(c.Replica(i), id)
			if rerr == nil && st == http.StatusOK && got == v2 {
				seen = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !seen {
			t.Fatalf("replica %d never saw the UPDATED value within %s", i, bound)
		}
	}
	t.Logf("update propagated to all replicas within %s", time.Since(start).Round(time.Millisecond))
}

// ── Oracle: a revoked PAT never authenticates on any replica after revoke ───
//
// Create a Personal Access Token on replica 0, confirm it authenticates on
// every replica, revoke it on replica 0, then confirm every OTHER replica
// stops accepting it within validTokenTTL (30s). A replica that positively
// cached the token may lag up to the TTL; past it is a defect.
func TestRevokedPATDenied(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)
	n := len(c.Replicas)

	rawToken, patID := c.createPAT(t, c.Replica(0), "mp1-revoke-"+fmt.Sprint(time.Now().UnixNano()))

	// Confirm the token authenticates on every replica first (so each has a
	// chance to positively cache it — the case the bound must survive).
	for i := range n {
		if st := c.authProbe(c.Replica(i), rawToken); st != http.StatusOK {
			t.Fatalf("fresh PAT not accepted on replica %d: HTTP %d", i, st)
		}
	}

	// Revoke on replica 0.
	env := c.rest(t, c.Replica(0), http.MethodDelete, fmt.Sprintf("/api/v1/auth/tokens/%d", patID), nil)
	if env.StatusCode != http.StatusNoContent && env.StatusCode != http.StatusOK {
		t.Fatalf("revoke PAT: HTTP %d: %s", env.StatusCode, env.Raw)
	}

	for i := range n {
		deadline := time.Now().Add(validTokenTTL + 5*time.Second)
		start := time.Now()
		denied := false
		for time.Now().Before(deadline) {
			if c.authProbe(c.Replica(i), rawToken) == http.StatusUnauthorized {
				denied = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !denied {
			t.Fatalf("revoked PAT still accepted by replica %d after %s — exceeds the documented %s window", i, time.Since(start), validTokenTTL)
		}
		t.Logf("replica %d denied the revoked PAT after %s (window %s)", i, time.Since(start).Round(time.Millisecond), validTokenTTL)
	}
}

// createPAT creates a Personal Access Token (POST /auth/tokens) and returns the
// raw token (shown once) and its id.
func (c *Cluster) createPAT(t *testing.T, s *harness.Server, name string) (raw string, id int) {
	t.Helper()
	env := c.rest(t, s, http.MethodPost, "/api/v1/auth/tokens", map[string]any{"name": name})
	if env.StatusCode != http.StatusCreated && env.StatusCode != http.StatusOK {
		t.Fatalf("create PAT: HTTP %d: %s", env.StatusCode, env.Raw)
	}
	var d struct {
		Token string `json:"token"`
		PAT   struct {
			ID int `json:"id"`
		} `json:"pat"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil || d.Token == "" || d.PAT.ID == 0 {
		t.Fatalf("create PAT: unexpected body %s (err=%v)", env.Raw, err)
	}
	return d.Token, d.PAT.ID
}

// authProbe hits an authenticated route with token and returns the status.
func (c *Cluster) authProbe(s *harness.Server, token string) int {
	env, err := c.restTokErr(s, token, http.MethodGet, "/api/v1/projects", nil)
	if err != nil {
		return 0
	}
	return env.StatusCode
}

// ── Oracle: the audit hash chain verifies with no gap or fork ───────────────
//
// After the fuzz corpus and the other oracles have driven many concurrent
// writes across all replicas (every create/update/delete appends an audit
// event under the ADR-029 advisory lock), the chain read straight from the
// shared database must verify VALID — no gap (a missing serialized append) and
// no fork (two heads from two replicas racing the lock). Runs verify-audit in
// --pg-dsn mode, which reads the chain directly without taking the running
// servers' presence lock.
func TestAuditChainVerifies(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	// Drive a short concurrent cross-replica burst so there is fresh audit
	// activity attributable to this test even if run in isolation: the creates
	// run at the same time on different replicas, so their appends contend for
	// the advisory lock.
	if _, errs := c.concurrentCreateSecrets("mp1-audit", 6); len(errs) > 0 {
		t.Fatalf("audit-burst creates failed: %v", errs)
	}

	out := c.verifyAudit(t)
	if !auditVerdictValid(out) {
		t.Fatalf("verify-audit produced no VALID verdict:\n%s", out)
	}
	t.Logf("verify-audit: %s", strings.TrimSpace(out))
}

// verifyAudit runs `admin verify-audit --json --pg-dsn <dsn>` against the
// shared database (read-only, does not take the running servers' lock) using
// replica 0's config dir + environment (which carry the key material and DB
// password). A non-zero exit fails the caller.
func (c *Cluster) verifyAudit(t *testing.T) string {
	t.Helper()
	s0 := c.Replica(0)
	args := []string{"admin", "verify-audit", "--json", "--pg-dsn", c.DSN}
	cmd := exec.Command(c.ServerBin, args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- the harness's own built binary, fixed args
	cmd.Dir = s0.Dir
	cmd.Env = s0.Env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("admin verify-audit exited non-zero: %v\n%s", err, out)
	}
	return string(out)
}

// auditVerdictValid reports whether verify-audit's --json report carries the
// exact VALID verdict. It matches the whole `"verdict": "VALID"` pair (the
// json.MarshalIndent form printVerifyAuditReport emits), so a BROKEN or any
// other verdict does not pass on the word VALID appearing elsewhere. verifyAudit
// also fails on a non-zero exit; this check does not rely on that alone.
func auditVerdictValid(out string) bool {
	return strings.Contains(out, `"verdict": "VALID"`)
}

// ── Oracle: a SIGKILLed replica leaves no stuck lock ────────────────────────
//
// SIGKILL one replica while all three are under write load, then confirm the
// surviving replicas keep committing writes (each of which appends to the
// audit chain under the ADR-029 advisory lock) within a bounded time — i.e.
// the dead replica's torn-down Postgres connections released any session locks
// it held (advisory locks are released when the holding connection ends) and
// did not wedge the chain. Uses its OWN cluster (SIGKILL would otherwise
// permanently remove a replica the shared fuzz loop depends on).
func TestKilledReplicaNoStuckLock(t *testing.T) {
	requirePG(t)
	c := StartCluster(t, 3, "")

	// Seed a secret and drive a brief burst so there is in-flight audit
	// activity around the kill.
	name := fmt.Sprintf("mp1-kill-%d", time.Now().UnixNano())
	recordCanary("kill-v0-" + name)
	id, st, err := c.createSecret(c.Replica(0), name, "kill-v0-"+name)
	if err != nil || (st != http.StatusCreated && st != http.StatusOK) {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	// Fire a few writes at the replica we are about to kill, concurrently,
	// then SIGKILL it mid-flight.
	victim := 1
	for i := range 3 {
		v := fmt.Sprintf("kill-inflight-%d-%s", i, name)
		recordCanary(v)
		go func() { _, _ = c.updateSecret(c.Replica(victim), id, v) }()
	}
	vs := c.Replicas[victim]
	if vs.Cmd == nil || vs.Cmd.Process == nil {
		t.Fatalf("victim replica has no process")
	}
	if kerr := vs.Cmd.Process.Kill(); kerr != nil {
		t.Fatalf("SIGKILL victim replica: %v", kerr)
	}
	select {
	case <-vs.Exited():
	case <-time.After(10 * time.Second):
		t.Fatalf("victim replica did not exit within 10s of SIGKILL")
	}
	t.Logf("victim replica %d SIGKILLed", victim)

	// A surviving replica must commit a write (→ audit append under the lock)
	// within a bounded time. If the dead replica had wedged the advisory lock,
	// this would hang/fail until Postgres noticed the dead backend.
	bound := 15 * time.Second
	deadline := time.Now().Add(bound)
	progressed := false
	var lastSt int
	var lastErr error
	start := time.Now()
	for time.Now().Before(deadline) {
		survivor := c.Replica(0) // replica 0 always survives
		v := fmt.Sprintf("post-kill-%d", time.Now().UnixNano())
		recordCanary(v)
		st, uerr := c.updateSecret(survivor, id, v)
		lastSt, lastErr = st, uerr
		if uerr == nil && st == http.StatusOK {
			progressed = true
			break
		}
		// also try replica 2
		v2 := fmt.Sprintf("post-kill2-%d", time.Now().UnixNano())
		recordCanary(v2)
		if st2, uerr2 := c.updateSecret(c.Replica(2), id, v2); uerr2 == nil && st2 == http.StatusOK {
			progressed = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !progressed {
		t.Fatalf("no surviving replica committed a write within %s of the SIGKILL (last status=%d err=%v) — possible stuck lock", bound, lastSt, lastErr)
	}
	t.Logf("surviving replica committed a write %s after the SIGKILL (bound %s)", time.Since(start).Round(time.Millisecond), bound)

	// ── Oracle #6 (restart half): the SIGKILLed replica reopens the shared
	// store without hand repair. ──────────────────────────────────────────────
	//
	// Restart the SAME victim process (same config dir, same port, same key
	// material) and confirm it becomes healthy and serves a fresh authenticated
	// write against the shared DB. A clean reopen requires the replica to
	// re-derive the KEK from the master password + on-disk salt, unseal the DEK,
	// re-attach to the already-migrated schema, and rebuild its connection pool —
	// all with no manual intervention. If the prior SIGKILL had left the store in
	// a state needing repair, the boot or the first write would fail here.
	// The restart truncates vs.LogPath, so keep the pre-SIGKILL log for the
	// post-run canary scan first.
	preKill := vs.LogPath + ".pre-restart"
	if err := os.Rename(vs.LogPath, preKill); err != nil {
		t.Fatalf("preserve the victim's pre-restart log: %v", err)
	}
	c.moveLog(vs.LogPath, preKill)
	serverEnv := append(append([]string{}, vs.Env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	harness.StartBackgroundProcess(t, vs, serverEnv)
	harness.WaitHealthy(t, vs)
	vr := fmt.Sprintf("post-restart-%d", time.Now().UnixNano())
	recordCanary(vr)
	if st, uerr := c.updateSecret(vs, id, vr); uerr != nil || st != http.StatusOK {
		t.Fatalf("restarted replica did not serve a write: status=%d err=%v — store did not reopen cleanly after SIGKILL", st, uerr)
	}
	t.Logf("SIGKILLed replica restarted, became healthy, and served a write against the shared store (no hand repair)")

	// And the chain still verifies (no fork/gap left by the torn-down replica).
	out := c.verifyAudit(t)
	if !auditVerdictValid(out) {
		t.Fatalf("after SIGKILL+restart, verify-audit produced no VALID verdict:\n%s", out)
	}
	t.Logf("after SIGKILL+restart, verify-audit: %s", strings.TrimSpace(out))
}

// ── Oracle: no secret value or key bytes appear in any replica log (canary) ──
//
// Every value written by this package is recorded as a canary (see the canary
// bookkeeping in cluster_fuzz_test.go for where the scan runs). Go runs Tests
// in source order and Fuzz targets after them, so this Test cannot see what
// the fuzz targets write, and under `-run '^$' -fuzz ...` no Test runs at all:
// the fuzz iterations and TestMain scan that output. This test adds a fresh,
// highly-distinctive canary of its own and scans the log output written so far.
func TestZZCanaryNoSecretInLogs(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	fresh := fmt.Sprintf("CANARY-%d-DO-NOT-LOG", time.Now().UnixNano())
	name := fmt.Sprintf("mp1-canary-%d", time.Now().UnixNano())
	recordCanary(fresh)
	if _, st, err := c.createSecret(c.Replica(0), name, fresh); err != nil || (st != http.StatusCreated && st != http.StatusOK) {
		t.Fatalf("canary create: st=%d err=%v", st, err)
	}
	// Read it back on every replica (exercises the value-read log path too).
	for i := range c.Replicas {
		_, _, _ = c.readSecretValue(c.Replica(i), 0) // id 0 ignored; just exercise
	}

	plantCanaryLeak(t, c, fresh)
	problems, logs := scanAllNewLogOutput(c)
	for _, p := range problems {
		t.Error(p)
	}
	t.Logf("canary scan: %d distinct secret values checked against %d replica logs", len(canarySnapshot()), logs)
}

// canaryMinLen is the shortest recorded value the log scan looks for; shorter
// values would match unrelated log text.
const canaryMinLen = 6

// canarySet is an exact multi-substring matcher: values bucketed by length, so
// a scan costs one map lookup per (window length, byte position), not one
// substring search per value. Over a long fuzz campaign the value set reaches
// hundreds of thousands, where a per-value strings.Contains over every log is
// far too slow.
type canarySet struct {
	minLen int
	byLen  map[int]map[string]struct{}
	lens   []int
	maxLen int
}

func newCanarySet(values []string, minLen int) *canarySet {
	s := &canarySet{minLen: minLen, byLen: map[int]map[string]struct{}{}}
	for _, v := range values {
		s.add(v)
	}
	return s
}

func (s *canarySet) add(v string) {
	if len(v) < s.minLen {
		return
	}
	m, ok := s.byLen[len(v)]
	if !ok {
		m = map[string]struct{}{}
		s.byLen[len(v)] = m
		s.lens = append(s.lens, len(v))
		s.maxLen = max(s.maxLen, len(v))
	}
	m[v] = struct{}{}
}

// find returns every distinct value of s that occurs in text.
func (s *canarySet) find(text []byte) []string {
	var hits []string
	seen := map[string]bool{}
	for _, l := range s.lens {
		m := s.byLen[l]
		for i := 0; i+l <= len(text); i++ {
			if _, ok := m[string(text[i:i+l])]; ok && !seen[string(text[i:i+l])] {
				v := string(text[i : i+l])
				seen[v] = true
				hits = append(hits, v)
			}
		}
	}
	return hits
}

// scanLogForSecrets returns every canary value (length >= minLen) that appears
// verbatim in logText. A non-empty result is a confidentiality leak.
func scanLogForSecrets(logText string, values []string, minLen int) []string {
	return newCanarySet(values, minLen).find([]byte(logText))
}

// scanNewLogOutput scans the log output of c written since its previous call
// (every log in logPaths, from the last scanned size minus an overlap of the
// longest pattern, so a value written across two scans is still seen) for any
// value in set and for c's raw DEK/salt key bytes. It returns one problem line
// per new hit and per log it could not read (an unscanned log is not a clean
// one), plus the number of logs it read. Complete only because every value is
// recorded before it is sent (recordCanary).
func (c *Cluster) scanNewLogOutput(set *canarySet) (problems []string, logs int) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if c.scanned == nil {
		c.scanned = map[string]int64{}
		c.reported = map[string]bool{}
	}
	keyCanaries := c.keyByteCanaries()
	overlap := set.maxLen
	for _, kc := range keyCanaries {
		overlap = max(overlap, len(kc))
	}
	report := func(p string) {
		if !c.reported[p] {
			c.reported[p] = true
			problems = append(problems, p)
		}
	}
	for _, path := range c.logPaths() {
		chunk, size, err := readFrom(path, max(0, c.scanned[path]-int64(overlap)))
		if err != nil {
			report(fmt.Sprintf("replica log %s unreadable, not scanned: %v", path, err))
			continue
		}
		c.scanned[path] = size
		logs++
		for _, v := range set.find(chunk) {
			report(fmt.Sprintf("CANARY HIT: secret value %q found in replica log %s", v, path))
		}
		for label, kc := range keyCanaries {
			if kc != "" && bytes.Contains(chunk, []byte(kc)) {
				report(fmt.Sprintf("CANARY HIT: key material (%s) found in replica log %s", label, path))
			}
		}
	}
	return problems, logs
}

// readFrom returns the bytes of path from offset off to its current end, and
// the end offset.
func readFrom(path string, off int64) ([]byte, int64, error) {
	f, err := os.Open(path) //nolint:gosec // harness-controlled path
	if err != nil {
		return nil, 0, err
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, 0, err
	}
	chunk, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	return chunk, off + int64(len(chunk)), nil
}

// keyByteCanaries returns distinctive substrings of the raw on-disk key files
// (dek.key, kek.salt) to search logs for. A hex-encoded chunk is used so a
// match is unambiguous even if the file bytes are not printable.
func (c *Cluster) keyByteCanaries() map[string]string {
	out := map[string]string{}
	if len(c.Replicas) == 0 {
		return out
	}
	dir := c.Replica(0).Dir
	for _, name := range []string{"dek.key", "kek.salt"} {
		raw, err := os.ReadFile(dir + "/keys/" + name) //nolint:gosec // harness temp path
		if err != nil {
			continue
		}
		if len(raw) > 8 {
			out[name+"(hex)"] = fmt.Sprintf("%x", raw[:min(16, len(raw))])
			out[name+"(raw)"] = string(raw)
		}
	}
	return out
}
