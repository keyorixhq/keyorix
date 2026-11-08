//go:build !windows

package main

// upgrade_path_fuzz_integration_test.go -- upgrade-path fuzz over released tags.
// Rules and success criteria: UPGRADE_PATH_FUZZ.md (same directory), committed
// before the first campaign run.
//
// For each released tag with a prebuilt keyorix-server binary
// ($KX_UPGRADE_BINDIR/<tag>, built by scripts/fuzzing/upgrade-path/build-tags.sh):
//  1. the OLD binary installs, bootstraps and is populated with seeded, fuzzed
//     data through the REST API (names, multi-version values with awkward bytes,
//     soft-deletes), then stopped; an OLD-format backup is taken with the OLD
//     binary;
//  2. clean upgrade: the HEAD binary migrates a copy; every value, the audit
//     chain, integrity, orphans, version counts are checked;
//  3. idempotence: migrating again changes neither schema nor data;
//  4. interrupted migration: the HEAD `migrate` is SIGKILLed at fuzzed points
//     (dir-change index / time fraction), then (a) a plain server start and
//     (b) a re-run of `migrate` must both reach the clean-upgrade state;
//  5. the OLD backup restores with the HEAD binary into a wiped host.
//
// Env: KX_UPGRADE_BINDIR (required), KX_UPGRADE_TAGS (comma list; default: every
// file in BINDIR), KX_UPGRADE_SEED, KX_UPGRADE_KILLS (kill iterations per tag,
// default 6; a tag needs >= 3 that landed, see R3), KX_UPGRADE_ARTIFACTS (failing post-kill snapshots).

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const upgPass = "upgrade-fuzz-passphrase-0001"

// upgMinLandedKills is R3's minimum of landed interrupted-migration kills per tag.
const upgMinLandedKills = 3

type upgSecret struct {
	Name     string
	Versions []string
	Deleted  bool
}

type upgLedger map[uint]*upgSecret

func (l upgLedger) asCrash() crashLedger {
	c := crashLedger{}
	for id, s := range l {
		if !s.Deleted {
			c[id] = s.Versions
		}
	}
	return c
}

// upgValue builds a fuzzed plaintext: unicode, whitespace/newlines, JSON-ish,
// long runs, but valid UTF-8 (the REST API carries JSON strings).
func upgValue(rng *rand.Rand, tag string) string {
	pieces := []string{
		"plain", "naïve-ключ-鍵-🔑", "line1\nline2\r\nline3", "  leading and trailing  ", `{"a":[1,2,{"b":null}]}`,
		"tab\tsep", "quote\"and'apos", "back\\slash", "%s %d {{x}} ${HOME}", "\u00a0nbsp", strings.Repeat("A", 1+rng.Intn(3000)),
	}
	var b strings.Builder
	for i := 1 + rng.Intn(4); i > 0; i-- {
		b.WriteString(pieces[rng.Intn(len(pieces))])
	}
	return fmt.Sprintf("%s|%x|%s", tag, rng.Int63(), b.String())
}

func upgName(rng *rand.Rand, i int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789-_"
	n := 3 + rng.Intn(40)
	b := make([]byte, n)
	for j := range b {
		b[j] = alpha[rng.Intn(len(alpha))]
	}
	return fmt.Sprintf("up%d-%s", i, b)
}

// upgInstall installs with bin in a fresh dir; reason != "" means the old
// release cannot be driven by this harness (reported BLOCKED, never PASS).
// Only releases that ship the admin CLI (v0.95.0 and later) can be installed by
// script: older ones need key files created by code that is not reachable from
// a binary (their fixtures are the committed internal/core/testdata ones).
func upgInstall(t *testing.T, bin string) (dir, port string, env []string, reason string) {
	t.Helper()
	dir = t.TempDir()
	env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+upgPass)
	// v0.95.x predates `init --dev` (its plain `init` already writes relaxed defaults).
	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		if !strings.Contains(out, "unknown flag") {
			return "", "", nil, fmt.Sprintf("old binary has no scriptable install: admin init --dev: %v: %s", err, tail(out, 200))
		}
		if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
			return "", "", nil, fmt.Sprintf("old binary has no scriptable install: admin init: %v: %s", err, tail(out, 200))
		}
	}
	for _, args := range [][]string{
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		if out, err := runAdmin(t, bin, dir, env, args...); err != nil {
			return "", "", nil, fmt.Sprintf("old binary has no scriptable install: admin %s: %v: %s", strings.Join(args, " "), err, tail(out, 200))
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml")) //nolint:gosec // test path
	if err != nil {
		return "", "", nil, "read config: " + err.Error()
	}
	port = freeTCPPort(t)
	text := strings.Replace(string(raw), `port: "8080"`, `port: "`+port+`"`, 1)
	text = strings.Replace(text, "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)
	if !strings.Contains(text, `port: "`+port+`"`) {
		return "", "", nil, "old config lacks the port line this harness rewrites"
	}
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(text), 0o600); err != nil {
		return "", "", nil, err.Error()
	}
	return dir, port, env, ""
}

func upgServer(t *testing.T, bin, dir, port string, env []string) *soakServer {
	return &soakServer{t: t, bin: bin, dir: dir, env: env, port: port, logPath: filepath.Join(dir, "upg-server.log")}
}

// upgPopulate runs the OLD server and fills it with fuzzed data.
func upgPopulate(t *testing.T, bin, dir, port string, env []string, rng *rand.Rand) (upgLedger, uint, uint, string) {
	srv := upgServer(t, bin, dir, port, env)
	srv.start("KEYORIX_BOOTSTRAP_TOKEN=" + soakBootstrapTok)
	if !srv.tryHealthy(soakHealthTimeout) {
		return nil, 0, 0, "old server did not start: " + tail(srv.logTail(), 400)
	}
	defer srv.stopGraceful()
	api := newSoakAPI(srv.baseURL())
	body, _ := json.Marshal(map[string]string{"username": soakAdminUser, "email": soakAdminEmail, "password": soakAdminPassword, "display_name": soakAdminUser})
	req, _ := http.NewRequest(http.MethodPost, srv.baseURL()+"/system/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", soakBootstrapTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, 0, 0, fmt.Sprintf("old bootstrap failed: err=%v", err)
	}
	_ = resp.Body.Close()
	code, data, err := api.do(http.MethodPost, "/auth/login", map[string]string{"username": soakAdminUser, "password": soakAdminPassword})
	var lg struct {
		Token string `json:"token"`
	}
	if err != nil || code != http.StatusOK || json.Unmarshal(data, &lg) != nil || lg.Token == "" {
		return nil, 0, 0, fmt.Sprintf("old login failed code=%d err=%v", code, err)
	}
	api.token = lg.Token
	mkID := func(path string, p map[string]string) (uint, string) {
		code, data, err := api.do(http.MethodPost, path, p)
		var d struct {
			ID uint `json:"id"`
		}
		if err != nil || code != http.StatusCreated || json.Unmarshal(data, &d) != nil || d.ID == 0 {
			return 0, fmt.Sprintf("POST %s code=%d err=%v", path, code, err)
		}
		return d.ID, ""
	}
	pid, why := mkID("/api/v1/projects", map[string]string{"name": "upg-project"})
	if why != "" {
		return nil, 0, 0, "old API: " + why
	}
	eid, why := mkID(fmt.Sprintf("/api/v1/projects/%d/environments", pid), map[string]string{"name": "upg-env"})
	if why != "" {
		return nil, 0, 0, "old API: " + why
	}
	led := upgLedger{}
	n := 10 + rng.Intn(15)
	for i := range n {
		name := upgName(rng, i)
		val := upgValue(rng, "v1")
		code, data, err := api.do(http.MethodPost, "/api/v1/secrets", map[string]any{"name": name, "value": val, "project_id": pid, "environment_id": eid, "type": "generic"})
		var d struct {
			ID uint `json:"id"`
		}
		if err != nil || code != http.StatusCreated || json.Unmarshal(data, &d) != nil || d.ID == 0 {
			return nil, 0, 0, fmt.Sprintf("old API create secret code=%d err=%v", code, err)
		}
		s := &upgSecret{Name: name, Versions: []string{val}}
		led[d.ID] = s
		for u := rng.Intn(5); u > 0; u-- {
			nv := upgValue(rng, fmt.Sprintf("v%d", len(s.Versions)+1))
			if code, _, err := api.do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", d.ID), map[string]any{"value": nv}); err != nil || code != http.StatusOK {
				return nil, 0, 0, fmt.Sprintf("old API update code=%d err=%v", code, err)
			}
			s.Versions = append(s.Versions, nv)
		}
		if i == 1 || i == 3 || rng.Intn(6) == 0 { // always soft-delete two, so every run covers deleted-secret rows
			if code, _, err := api.do(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", d.ID), nil); err == nil && (code == http.StatusOK || code == http.StatusNoContent) {
				s.Deleted = true
			}
		}
	}
	return led, pid, eid, ""
}

// dbFingerprint hashes schema + data of the tables an upgrade must not alter
// semantically. Schema part and data part are returned separately.
func dbFingerprint(t *testing.T, dir string) (schema, data string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "keyorix.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT type||':'||name||':'||COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		t.Fatalf("schema query: %v", err)
	}
	var parts []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("schema scan: %v", err)
		}
		parts = append(parts, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("schema rows: %v", err)
	}
	_ = rows.Close()
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	schema = hex.EncodeToString(h[:])
	dh := sha256.New()
	for _, q := range []string{
		`SELECT id, secret_node_id, version_number, hex(encrypted_value) FROM secret_versions ORDER BY id`,
		`SELECT id, name, COALESCE(deleted_at,'') FROM secret_nodes ORDER BY id`,
	} {
		// A failing read must fail the test: two identically broken reads would
		// otherwise hash equal and make the S3 comparison pass vacuously.
		r, err := db.Query(q)
		if err != nil {
			t.Fatalf("data fingerprint query %q: %v", q, err)
		}
		cols, err := r.Columns()
		if err != nil {
			t.Fatalf("data fingerprint columns %q: %v", q, err)
		}
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatalf("data fingerprint scan %q: %v", q, err)
			}
			_, _ = fmt.Fprintf(dh, "%v\n", vals)
		}
		if err := r.Err(); err != nil {
			t.Fatalf("data fingerprint rows %q: %v", q, err)
		}
		_ = r.Close()
	}
	return schema, hex.EncodeToString(dh.Sum(nil))
}

// upgKillLanded reports whether a planned kill really interrupted the child
// (R3 counts only those). change/time plans land only if the child died of
// SIGKILL: runChild also sets killed when the signal races a child that had
// already exited. A diskfull plan has no signal; it lands if the child failed.
func upgKillLanded(plan killPlan, exitErr error) bool {
	var ee *exec.ExitError
	if !errors.As(exitErr, &ee) {
		return false
	}
	if plan.kind == "diskfull" {
		return true
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

type upgCtx struct {
	led    upgLedger
	w      *crashWorld // reuse of checker plumbing
	ids    []uint
	expect crashLedger
}

// verifyUpgraded boots HEAD on dir and checks values + quiescent invariants.
func (u *upgCtx) verifyUpgraded(dir, port string) []string {
	var v []string
	u.w.dir, u.w.port = dir, port
	obs, up, lg := u.w.bootAndObserve(dir, upgPass, u.ids)
	if !up {
		return []string{"HEAD server does not start on upgraded data: " + tail(lg, 600)}
	}
	if _, ok := matchState(obs, u.expect); !ok {
		v = append(v, "values differ from the pre-upgrade ledger: "+diffObs(obs, []crashLedger{u.expect}))
	}
	return append(v, u.w.checkQuiescent(dir, upgPass, u.expect)...)
}

func TestUpgradePathFuzz(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes; skipped with -short")
	}
	binDir := os.Getenv("KX_UPGRADE_BINDIR")
	if binDir == "" {
		t.Skip("KX_UPGRADE_BINDIR not set (see scripts/fuzzing/upgrade-path/build-tags.sh)")
	}
	var tags []string
	if s := os.Getenv("KX_UPGRADE_TAGS"); s != "" {
		tags = strings.Split(s, ",")
	} else {
		ents, _ := os.ReadDir(binDir)
		for _, e := range ents {
			if !e.IsDir() && strings.HasPrefix(e.Name(), "v") {
				tags = append(tags, e.Name())
			}
		}
		sort.Strings(tags)
	}
	seed := int64(soakEnvInt("KX_UPGRADE_SEED", int(time.Now().UnixNano()%1_000_000)+1))
	kills := soakEnvInt("KX_UPGRADE_KILLS", 6) // not every attempt lands; R3 needs >= upgMinLandedKills that do
	artifacts := os.Getenv("KX_UPGRADE_ARTIFACTS")
	t.Logf("upgrade-path fuzz: seed=%d kills/tag=%d tags=%v", seed, kills, tags)
	head := fuzzHeadBinary(t)

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed ^ int64(len(tag))*7919 ^ int64(tag[len(tag)-1]))) //nolint:gosec // test randomness, seed logged
			oldBin := filepath.Join(binDir, tag)
			if _, err := os.Stat(oldBin); err != nil {
				t.Skipf("BLOCKED: no binary for %s", tag)
			}
			dir, port, env, why := upgInstall(t, oldBin)
			if why != "" {
				t.Skipf("BLOCKED(%s): %s", tag, why)
			}
			led, _, _, why := upgPopulate(t, oldBin, dir, port, env, rng)
			if why != "" {
				t.Skipf("BLOCKED(%s): %s", tag, why)
			}
			// Old-format backup, taken by the OLD binary (server is stopped).
			oldBackup := filepath.Join(dir, "old-backup.tar.gz")
			backupOK := true
			if out, err := runAdmin(t, oldBin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./old-backup.tar.gz"); err != nil {
				backupOK = false
				t.Logf("NOTE(%s): old binary cannot take a backup (%v): %s", tag, err, tail(out, 200))
			}
			if !backupOK {
				// R2: without S5 the tag is not covered. Reported BLOCKED (never PASS)
				// once the remaining scenarios have run; a failure above still fails the tag.
				defer t.Skipf("BLOCKED(%s): S5 not run, the old binary cannot take a backup", tag)
			}
			nDel := 0
			for _, sec := range led {
				if sec.Deleted {
					nDel++
				}
			}
			t.Logf("%s: populated %d secrets (%d soft-deleted), %d total versions", tag, len(led), nDel, func() int {
				n := 0
				for _, sec := range led {
					n += len(sec.Versions)
				}
				return n
			}())
			u := &upgCtx{led: led, ids: func() []uint {
				var ids []uint
				for id := range led {
					ids = append(ids, id)
				}
				slices.Sort(ids)
				return ids
			}(), expect: led.asCrash()}
			u.w = &crashWorld{t: t, bin: head}
			// Deleted ids must read as gone: observe() maps unknown ids to "<gone>"
			// via latest(), which matches expect lacking them.

			migrate := func(d string) (string, error) {
				return runAdmin(t, head, d, append(baseEnv(d), "KEYORIX_MASTER_PASSWORD="+upgPass), "migrate", "--config", "./keyorix.yaml")
			}
			// S2: clean upgrade.
			clean := t.TempDir()
			copyTree(t, dir, clean)
			if out, err := migrate(clean); err != nil {
				t.Errorf("S2 clean upgrade: HEAD migrate failed on %s data: %v\n%s", tag, err, tail(out, 600))
				return
			}
			if v := u.verifyUpgraded(clean, port); len(v) > 0 {
				t.Errorf("S2 clean upgrade from %s: %s", tag, strings.Join(v, "\n  "))
			}
			// s1 is the schema after the S2 verification boot: the reference for S4 (a),
			// which also ends with a boot. S4 (b) compares migrate-only schemas (cleanSchema).
			s1, _ := dbFingerprint(t, clean)
			if sOld, _ := dbFingerprint(t, dir); sOld == s1 {
				t.Logf("NOTE(%s): HEAD migration left the schema fingerprint unchanged (no schema delta between this tag and HEAD)", tag)
			}
			// S3: idempotence (fingerprint taken AFTER the verification boot too,
			// since a server start may legitimately touch state; compare migrate-only).
			clean2 := t.TempDir()
			copyTree(t, dir, clean2)
			if out, err := migrate(clean2); err != nil {
				t.Errorf("S3 first migrate failed: %v\n%s", err, tail(out, 400))
				return
			}
			sA, dA := dbFingerprint(t, clean2)
			if out, err := migrate(clean2); err != nil {
				t.Errorf("S3 second migrate failed: %v\n%s", err, tail(out, 400))
			}
			sB, dB := dbFingerprint(t, clean2)
			if sA != sB || dA != dB {
				t.Errorf("S3 migrate is not idempotent on %s data (schema same=%v, data same=%v)", tag, sA == sB, dA == dB)
			}
			cleanSchema := sA
			// S4: interrupted migration.
			calDir := t.TempDir()
			copyTree(t, dir, calDir)
			w := &crashWorld{t: t, bin: head, dir: calDir}
			_, nChanges, calDur, calOut, calErr := runChild(w, calDir, upgPass, []string{"migrate", "--config", "./keyorix.yaml"}, nil)
			if calErr != nil {
				t.Fatalf("S4 calibration migrate failed (kill points would all land at t=0): %v\n%s", calErr, tail(calOut, 400))
			}
			landed := map[string]int{}
			for i := range kills {
				var plan killPlan
				switch i % 3 {
				case 0:
					// n >= 1: n=0 kills on the first poll, before migration did any work.
					plan = killPlan{kind: "change", n: 1 + rng.Intn(max(nChanges, 1))}
				case 1:
					plan = killPlan{kind: "time", after: time.Duration(rng.Int63n(int64(calDur) + 1))}
				default:
					plan = killPlan{kind: "diskfull", ulimitBl: 1 + rng.Intn(4096)}
				}
				d := t.TempDir()
				copyTree(t, dir, d)
				_, _, _, _, killErr := runChild(w, d, upgPass, []string{"migrate", "--config", "./keyorix.yaml"}, &plan)
				killed := upgKillLanded(plan, killErr)
				if killed {
					landed[plan.kind]++
				}
				snap := t.TempDir()
				copyTree(t, d, filepath.Join(snap, "install"))
				var viol []string
				// (a) plain server start (auto-migration path): values (verifyUpgraded) and
				// the schema after that boot must equal the clean upgrade's (s1).
				if va := u.verifyUpgraded(d, port); len(va) > 0 {
					viol = append(viol, "(a) server start after killed migrate: "+strings.Join(va, "; "))
				} else if sa, _ := dbFingerprint(t, d); sa != s1 {
					viol = append(viol, "(a) schema after server start on a killed migrate differs from clean upgrade")
				}
				// (b) re-run migrate on a fresh copy of the same snapshot: schema right after
				// the migrate (before any boot) equals cleanSchema, then values via a boot.
				d2 := t.TempDir()
				copyTree(t, filepath.Join(snap, "install"), d2)
				if out, err := migrate(d2); err != nil {
					viol = append(viol, fmt.Sprintf("(b) re-run migrate after kill failed: %v %s", err, tail(out, 300)))
				} else {
					if sx, _ := dbFingerprint(t, d2); sx != cleanSchema {
						viol = append(viol, "(b) schema after kill+re-run migrate differs from clean upgrade")
					}
					if vb := u.verifyUpgraded(d2, port); len(vb) > 0 {
						viol = append(viol, "(b) values after kill+re-run migrate: "+strings.Join(vb, "; "))
					}
				}
				t.Logf("%s S4 iter %d plan=%s landed=%v violations=%d", tag, i, plan, killed, len(viol))
				if len(viol) > 0 {
					dest := snap
					if artifacts != "" {
						dest = filepath.Join(artifacts, fmt.Sprintf("%s-seed%d-iter%d", tag, seed, i))
						_ = os.MkdirAll(dest, 0o700)
						copyTree(t, filepath.Join(snap, "install"), filepath.Join(dest, "install"))
					}
					t.Errorf("VIOLATION %s S4 iter %d plan=%s snapshot=%s:\n  %s", tag, i, plan, dest, strings.Join(viol, "\n  "))
				}
			}
			nLanded := landed["change"] + landed["time"] + landed["diskfull"]
			t.Logf("%s S4 kills landed: %d of %d attempts (change=%d time=%d diskfull=%d)", tag, nLanded, kills, landed["change"], landed["time"], landed["diskfull"])
			if nLanded < upgMinLandedKills {
				t.Errorf("R3 not met for %s: %d kills landed of %d attempts, need >= %d (raise KX_UPGRADE_KILLS)", tag, nLanded, kills, upgMinLandedKills)
			}
			// S5: OLD backup restores with HEAD into a wiped host.
			if backupOK {
				rd := t.TempDir()
				renv := append(baseEnv(rd), "KEYORIX_MASTER_PASSWORD="+upgPass)
				if out, err := runAdmin(t, head, rd, renv, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
					t.Errorf("S5 setup: head init: %v %s", err, tail(out, 200))
					return
				}
				// Same wipe the existing round-trip test does: db + keys.
				_ = os.Remove(filepath.Join(rd, "keyorix.db"))
				_ = os.RemoveAll(filepath.Join(rd, "keys"))
				copyTreeFile(t, oldBackup, filepath.Join(rd, "old-backup.tar.gz"))
				// Same port: the old config's port is what the restored host uses.
				if out, err := runAdmin(t, head, rd, renv, "restore", "--config", "./keyorix.yaml", "--input", "./old-backup.tar.gz"); err != nil {
					// Diagnosis for classification (R4): does the OLD binary restore its own
					// backup, and how many soft-deleted secrets did the ledger hold?
					deleted := 0
					for _, sec := range led {
						if sec.Deleted {
							deleted++
						}
					}
					od := t.TempDir()
					oenv := append(baseEnv(od), "KEYORIX_MASTER_PASSWORD="+upgPass)
					_, _ = runAdmin(t, oldBin, od, oenv, "init", "--config", "./keyorix.yaml")
					_ = os.Remove(filepath.Join(od, "keyorix.db"))
					_ = os.RemoveAll(filepath.Join(od, "keys"))
					copyTreeFile(t, oldBackup, filepath.Join(od, "old-backup.tar.gz"))
					oout, oerr := runAdmin(t, oldBin, od, oenv, "restore", "--config", "./keyorix.yaml", "--input", "./old-backup.tar.gz")
					t.Errorf("S5 HEAD cannot restore the %s backup (ledger has %d soft-deleted of %d secrets; OLD binary restoring its own backup: err=%v): %v\n%s\n--- old binary said:\n%s",
						tag, deleted, len(led), oerr, err, tail(out, 700), tail(oout, 500))
					return
				}
				// Make the restored host listen on a known port.
				if raw, err := os.ReadFile(filepath.Join(rd, "keyorix.yaml")); err == nil { //nolint:gosec // test path
					_ = os.WriteFile(filepath.Join(rd, "keyorix.yaml"), []byte(strings.Replace(strings.Replace(string(raw), `port: "8080"`, `port: "`+port+`"`, 1), "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)), 0o600)
				}
				if v := u.verifyUpgraded(rd, port); len(v) > 0 {
					t.Errorf("S5 %s backup restored with HEAD but: %s", tag, strings.Join(v, "\n  "))
				}
			}
		})
	}
}

func copyTreeFile(t *testing.T, src, dst string) { copyTree2(t, src, dst) }

// TestUpgradePathChecker_Planted (pre-registered R1/U1): after a clean upgrade,
// one flipped ciphertext byte must make the S2 verification path fail.
func TestUpgradePathChecker_Planted(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes; skipped with -short")
	}
	binDir := os.Getenv("KX_UPGRADE_BINDIR")
	tag := os.Getenv("KX_UPGRADE_PLANT_TAG")
	if binDir == "" || tag == "" {
		t.Skip("KX_UPGRADE_BINDIR / KX_UPGRADE_PLANT_TAG not set")
	}
	rng := rand.New(rand.NewSource(int64(soakEnvInt("KX_UPGRADE_SEED", 1)))) //nolint:gosec // test randomness
	head := fuzzHeadBinary(t)
	dir, port, env, why := upgInstall(t, filepath.Join(binDir, tag))
	if why != "" {
		t.Skipf("BLOCKED: %s", why)
	}
	led, _, _, why := upgPopulate(t, filepath.Join(binDir, tag), dir, port, env, rng)
	if why != "" {
		t.Skipf("BLOCKED: %s", why)
	}
	var ids []uint
	for id := range led {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	u := &upgCtx{led: led, ids: ids, expect: led.asCrash(), w: &crashWorld{t: t, bin: head}}
	if out, err := runAdmin(t, head, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+upgPass), "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("migrate: %v %s", err, tail(out, 300))
	}
	if v := u.verifyUpgraded(dir, port); len(v) != 0 {
		t.Fatalf("CONTROL: clean upgrade from %s reports violations: %v", tag, v)
	}
	var victim uint
	for id, s := range led {
		if !s.Deleted {
			victim = id
			break
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "keyorix.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE secret_versions SET encrypted_value = substr(encrypted_value,1,length(encrypted_value)-1) || char(unicode(substr(encrypted_value,length(encrypted_value),1)) % 255 + 1) WHERE secret_node_id=? AND version_number=(SELECT MAX(version_number) FROM secret_versions WHERE secret_node_id=?)`, victim, victim); err != nil {
		t.Fatalf("plant: %v", err)
	}
	_ = db.Close()
	if v := u.verifyUpgraded(dir, port); len(v) == 0 {
		t.Errorf("U1: flipped ciphertext byte after upgrade was NOT detected")
	} else {
		t.Logf("U1 detected: %s", tail(v[0], 200))
	}
}
