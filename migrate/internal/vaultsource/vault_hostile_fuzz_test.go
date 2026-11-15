package vaultsource_test

// vault_hostile_fuzz_test.go: FuzzVaultSourceHostileWalk is the hostile-backend
// record-and-mutate target for the migrate tool's Vault KV reader — the code that makes
// first contact with every customer's Vault and feeds the import write path. It drives the
// REAL vaultsource.Client (public API only: New + Walk) against a fake Vault HTTP server
// whose mount-version, LIST, and KV-v2 READ responses are mutated by the fuzz-decoded
// program (JSON field ops, status/content-type/encoding/framing/redirect/network faults;
// rules: migrate/internal/hostile/RULES.md).
//
// Oracles (what each does NOT verify is stated):
//   - O1 NO-PANIC / O2 NO-HANG / O4 BOUNDED-WORK via hostile.Harness.Run. O2 gives Walk a
//     500ms context; a client that ignores it is a finding. Does NOT bound CPU within the
//     deadline, nor assert the pristine path is fast (pristine gets 10x).
//   - O6 LIVENESS: the pristine program's Walk returns exactly the one planted entry with no
//     error. A target whose control fails is invalid (reported as HARNESS).
//   - O7/(b) NO-LEAKAGE: the canary is planted as the secret VALUE (the thing the tool imports
//     and must never surface in an error/log). Walk's returned error, every Skipped.Reason,
//     and captured slog output must not contain it. The canary appearing in a returned
//     Entry.Value is the imported value, NOT a leak. Does NOT capture a private (non-slog)
//     logger (vaultsource has none today) and does NOT scan the eventual report rendering
//     (covered by the cmd-level target).
//   - O8 BOUNDED-REQUESTS/(a): the walk stays within a large runaway/infinite-loop backstop;
//     a hostile LIST legitimately fans out to one READ per key, so a small ceiling is the wrong
//     oracle here (genuine DoS is caught by O2/O4 instead). Does NOT test unbounded recursion
//     DEPTH — the harness's own Valid tree must terminate for O6, so a Vault that returns a
//     folder key at every level cannot be exercised through this pristine-must-succeed harness.
//     Walk's depth cap (maxWalkDepth, campaign FINDING F4) is covered precisely by the
//     deterministic TestWalk_DepthCapped instead.
//   - O9 SSRF-ISH/(c): the client declares it never follows redirects (CheckRedirect =
//     ErrUseLastResponse); the sentinel internal-address server must receive zero requests.
//     Loopback sentinel: this tests redirect policy, not address filtering.
//   - O5/(e) FAIL-CLOSED: if Walk reports success and returns the leaf entry, the READ
//     response it consumed must have been completely delivered with an accepted status and
//     must strict-decode to the same value (no truncated/partial success). Does NOT assert
//     per-request delivery for a multi-leaf tree (the tree here is one leaf by construction).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/hostile"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

const hostileVaultToken = "kx-hostile-vault-token-77c1"

// vaultHostileRoutes serves a terminating one-leaf KV v2 tree under mount "secret":
// mount-version=2, LIST root -> ["db"], READ secret/data/db -> {"password": <canary>}.
// The canary is the secret VALUE (what must never leak into an error/log).
func vaultHostileRoutes() []hostile.Route {
	js := func(s string) hostile.Resp { return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)} }
	return []hostile.Route{
		{Name: "mount", Method: "GET", Prefix: "/v1/sys/internal/ui/mounts", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"data":{"path":"secret/","type":"kv","options":{"version":"2"}}}`)
		}},
		{Name: "list", Method: "GET", Prefix: "/v1/secret/metadata", Valid: func(_ int, r *http.Request) hostile.Resp {
			sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata"), "/")
			if sub == "" {
				return js(`{"data":{"keys":["db"]}}`)
			}
			return js(`{"data":{"keys":[]}}`) // any deeper path is a leaf (terminates the walk)
		}},
		{Name: "read", Method: "GET", Prefix: "/v1/secret/data", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"data":{"data":{"password":"` + hostile.Canary + `"},"metadata":{"version":3,"created_time":"2026-01-01T00:00:00Z","destroyed":false}}}`)
		}},
	}
}

// strictVaultV2Secret decodes the READ body per Vault's documented KV v2 wire format and
// returns the single field value, written independently of vaultsource.read.
func strictVaultV2Secret(body []byte) (string, bool) {
	var env struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil || len(env.Data.Data) == 0 || string(env.Data.Data) == "null" {
		return "", false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(env.Data.Data, &m) != nil || len(m) != 1 {
		return "", false
	}
	for _, raw := range m {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s, true
		}
		return string(raw), true
	}
	return "", false
}

func FuzzVaultSourceHostileWalk(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Route: 0, Ops: []hostile.Op{{Code: 2, A: 2, B: 1}}},  // mount version -> number
		{Route: 1, Ops: []hostile.Op{{Code: 7, A: 2, B: 1}}},  // oversized LIST keys (fan-out)
		{Route: 1, Ops: []hostile.Op{{Code: 6, A: 2, B: 11}}}, // key -> "../../etc/passwd"
		{Route: 2, Ops: []hostile.Op{{Code: 0, A: 2}}},        // read data -> null
		{Route: 2, Frame: 3}, // read cl-too-short (truncated)
		{Route: 2, Fault: 2}, // read rst-mid-body
		{Route: 2, Enc: 2},   // read gzip bomb
		{Route: 2, Ops: []hostile.Op{{Code: 4, A: 3, B: 3}}}, // huge value string
		{Route: 2, Ops: []hostile.Op{{Code: 5, A: 2, B: 3}}}, // deep nesting
		// FINDING F3 (FIXED): a READ answered with a 3xx the client refuses to follow must be an
		// error, not an import. This seed used to trip O5 (the 302 body was parsed as the secret);
		// now vaultsource rejects any non-200/404 READ status, so Walk errors and imports nothing.
		// Seeded in the default corpus so `go test` exercises the fixed path directly. See
		// INV-VAULTSOURCE-non-2xx-read-is-an-error and TestWalk_RedirectReadBodyIsNotImported.
		{Route: 2, Redir: 1}, // read served as a 302 redirect (not followed, body not parsed)
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: vaultHostileRoutes(), Program: p,
			Credentials: []string{hostileVaultToken},
			// A hostile LIST can legitimately fan out to one READ per listed key, so a small
			// request ceiling is the WRONG oracle for a recursive walk (it would fire on
			// expected work). This is a pure runaway/infinite-loop backstop; genuine DoS is
			// caught by O2 (no-hang) and O4 (bounded alloc). The mount-lookup redundancy is a
			// separate, precise check below (FINDING F2).
			RequestCeiling: 200000,
			// Go's net/http.Transport transparently retries an idempotent GET that received NO
			// response bytes (e.g. a server that accepts then closes the connection before writing
			// anything). vaultsource issues plain GETs, so a network-fault first attempt is
			// re-sent by the stdlib and the SECOND, complete exchange is the one the client
			// actually parses. Retries makes the O5 delivery oracle judge that final exchange
			// (RULES.md amendment #4), not the retried-away attempt — the final exchange is still
			// fully checked for complete delivery, accepted status, and a matching body, so this
			// does not weaken the oracle. Without it, an accept-close+redirect-shaped program is a
			// harness-calibration false positive (campaign artifact A5), not a product defect.
			Retries: true,
		})
		defer h.Close()

		var entries []vaultsource.Entry
		var skipped []vaultsource.Skipped
		errWalk := h.Run("vaultsource.Walk", func(ctx context.Context) error {
			c, err := vaultsource.New(ctx, vaultsource.Config{
				Addr: h.URL(), Mount: "secret", Token: hostileVaultToken,
			})
			if err != nil {
				return err
			}
			entries, skipped, err = c.Walk(ctx, "", false)
			return err
		})

		// O7/(b): the canary (the secret VALUE) must not appear in the error text, any
		// Skipped reason, or captured logs. It MAY appear in an Entry.Value (that is the import).
		if errWalk != nil {
			h.CheckLeak("vaultsource.Walk", errWalk.Error())
		}
		for _, s := range skipped {
			if strings.Contains(s.Reason, hostile.Canary) {
				h.Violate("O7 LEAK: Skipped.Reason for %q contains the secret canary", s.Path)
			}
		}

		// O6 LIVENESS: pristine Walk returns exactly the planted entry.
		if p.Pristine() {
			if errWalk != nil {
				h.Violate("O6 LIVENESS: pristine Walk errored: %v (unmatched: %v)", errWalk, h.Unmatched())
			} else if len(entries) != 1 || entries[0].Path != "db" || entries[0].Field != "password" || entries[0].Value != hostile.Canary {
				h.Violate("O6 LIVENESS: pristine Walk returned %#v (want one db#password=canary)", entries)
			}
		}

		// O5/(e) FAIL-CLOSED (delivery): a successful Walk that produced the leaf entry must
		// have consumed a fully-delivered READ with an accepted (200) status — not a truncated,
		// faulted, or redirected response. Value-level faithfulness beyond delivery is NOT
		// asserted: vaultsource stringifies a non-string KV field with fmt "%v" by design, which
		// a raw-JSON strict decoder would not match — that documented coercion is an
		// EXPECTED-DIFFERENCE, not a fail-closed concern. The delivery classification is the
		// sharp oracle (e) edge and is what exposes FINDING F3 (3xx body parsed as the secret).
		if errWalk == nil {
			imported := false
			for i := range entries {
				if entries[i].Path == "db" {
					imported = true
				}
			}
			if imported {
				contentOK := func(b []byte) bool { _, ok := strictVaultV2Secret(b); return ok }
				if _, kind := h.Delivery("read", contentOK); kind == "bad" {
					h.Violate("O5/incomplete: Walk imported the db leaf although the READ it consumed was incomplete, redirected, or non-200")
				}
			}
		}

		// FINDING F2 (FIXED): resolveKVMountVersion's per-client cache now holds a single mount
		// version (a Client targets exactly one mount), so a whole Walk resolves it at most once
		// instead of once per list() AND once per read(). This is now a default guard: the mount
		// endpoint must be hit at most once per Walk. See INV-VAULTSOURCE-mount-version-resolved-once
		// and TestWalk_ResolvesMountVersionOnce.
		if mountHits := len(h.Served("mount")); mountHits > 1 {
			h.Violate("FINDING F2: resolveKVMountVersion resolved the mount version %d times in one Walk (the per-client cache must hit; exactly one round-trip expected)", mountHits)
		}

		h.Finish(t.Fatalf)
	})
}
