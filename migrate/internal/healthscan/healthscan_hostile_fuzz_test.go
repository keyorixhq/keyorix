package healthscan_test

// healthscan_hostile_fuzz_test.go: FuzzHealthscanHostileVault drives the ENTIRE
// `keyorix-migrate vault scan` check suite (healthscan.Run over the real registered checks)
// against a fake Vault whose every response is mutated by the fuzz program, then renders all
// three report formats (JSON, Markdown, HTML). `vault scan` runs against a customer's LIVE
// Vault in a PAID assessment, so a crash, a hang, or — worst of all — the Vault TOKEN leaking
// into the delivered report is a direct, customer-visible failure.
//
// A single catch-all route serves a generic Vault-shaped envelope to every /v1/ path; the
// program mutates it (status/content-type/encoding/framing/redirect/network fault + JSON field
// ops). healthscan is panic-safe by contract (RunChecks recovers each check), so the point is
// not to make a check crash but to prove the suite stays live, bounded, and leak-free on
// arbitrary hostile responses.
//
// Oracles (what each does NOT verify):
//   - O1 NO-PANIC / O2 NO-HANG / O4 BOUNDED-WORK via hostile.Harness.Run around the whole scan.
//     Does NOT attribute a hang to a specific check (the whole suite is timed as one unit).
//   - O6 LIVENESS: a scan always returns a non-nil *Report that renders to all three formats
//     without error (healthscan folds every check failure into NotChecked by design). Does NOT
//     assert the findings are correct — only that the suite completes.
//   - O7/(b) NO-LEAKAGE (credential): the Vault TOKEN must never appear in the rendered JSON,
//     Markdown, or HTML report, nor in captured slog output. Does NOT treat a hostile RESPONSE
//     field echoed into a Finding.Evidence as a leak — healthscan reads METADATA only, never a
//     secret value, so response echo is the "echo" class, not a secret disclosure; only the
//     credential is asserted here.
//   - O8 BOUNDED-REQUESTS: the whole suite stays within a generous request ceiling (no
//     unbounded pagination/redirect loop). Does NOT pin an exact per-check request count.
//   - O9 SSRF-ISH: the sentinel internal-address server receives zero requests (the client
//     refuses to follow redirects). Loopback sentinel: redirect policy, not address filtering.

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
	"github.com/keyorixhq/keyorix/migrate/internal/hostile"
)

const hostileScanToken = "kx-hostile-scan-token-b4e2-SECRET"

// healthscanHostileRoutes serves one generic, plausible Vault envelope for every /v1/ path;
// the program mutates it. The envelope carries fields several checks read (data, keys,
// options, policies, sealed, version, mounts) so mutations exercise many parsers.
func healthscanHostileRoutes() []hostile.Route {
	const envelope = `{"request_id":"r","data":{"sealed":false,"version":"1.15.0","keys":["a","b/"],` +
		`"policies":["default","root"],"options":{"version":"2"},"type":"kv",` +
		`"secret/":{"type":"kv","options":{"version":"2"}},"ttl":3600,"n":2,` +
		`"disabled":false,"deletion_time":"","destroyed":false},"policies":["default"]}`
	return []hostile.Route{
		{Name: "vault", Method: "", Prefix: "/v1/", Valid: func(int, *http.Request) hostile.Resp {
			return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(envelope)}
		}},
	}
}

func FuzzHealthscanHostileVault(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Ops: []hostile.Op{{Code: 2, A: 1, B: 1}}}, // sealed -> number
		{Ops: []hostile.Op{{Code: 7, A: 3, B: 1}}}, // oversized keys list
		{Ops: []hostile.Op{{Code: 4, A: 2, B: 2}}}, // huge string
		{Ops: []hostile.Op{{Code: 5, A: 1, B: 3}}}, // deep nesting
		{Enc: 2},                                   // gzip bomb
		{Frame: 3},                                 // truncated
		{Fault: 2},                                 // rst mid-body
		{Redir: 1},                                 // redirect to attacker
		{Status: 12},                               // 403 on everything
		{CT: 7},                                     // application/jsonx content type
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: healthscanHostileRoutes(), Program: p,
			Credentials:    []string{hostileScanToken},
			CallTimeout:    2000000000, // 2s: the whole suite, not one request
			RequestCeiling: 2000,
		})
		defer h.Close()

		var report *healthscan.Report
		_ = h.Run("healthscan.Run", func(ctx context.Context) error {
			c, err := healthscan.New(ctx, healthscan.Config{Addr: h.URL(), Token: hostileScanToken}, &bytes.Buffer{})
			if err != nil {
				return err
			}
			report = healthscan.Run(ctx, c, h.URL(), "keyorix-migrate test")
			return nil
		})

		if p.Pristine() && report == nil {
			h.Violate("O6 LIVENESS: pristine scan returned a nil report")
		}

		// O6 + O7: render all three report formats and scan them (and captured logs) for the token.
		if report != nil {
			var jsonBuf, mdBuf, htmlBuf bytes.Buffer
			if err := healthscan.WriteJSON(&jsonBuf, report); err != nil {
				h.Violate("O6: WriteJSON failed: %v", err)
			}
			if err := healthscan.WriteMarkdown(&mdBuf, report); err != nil {
				h.Violate("O6: WriteMarkdown failed: %v", err)
			}
			if err := healthscan.WriteHTML(&htmlBuf, report); err != nil {
				h.Violate("O6: WriteHTML failed: %v", err)
			}
			for name, out := range map[string]string{"json": jsonBuf.String(), "markdown": mdBuf.String(), "html": htmlBuf.String()} {
				if strings.Contains(out, hostileScanToken) {
					h.Violate("O7 LEAK: the Vault token appears in the rendered %s report", name)
				}
			}
			if strings.Contains(h.Logs(), hostileScanToken) {
				h.Violate("O7 LEAK: the Vault token appears in captured log output")
			}
		}

		h.Finish(t.Fatalf)
	})
}
