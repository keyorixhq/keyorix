package http

// FuzzMultiTenantIsolation is the two-tenant confidentiality DAST fuzzer: it drives a
// fuzzer-chosen interleaving of two principals' requests against the REAL wired stack
// (NewRouter + auth middleware + core + crypto + storage) and asserts the isolation
// boundary a secrets manager lives or dies on — principal A can never read, enumerate, or
// confirm the existence of principal B's secrets.
//
// Two fully disjoint tenants (reuses buildAPIFuzzWorld's projA/projB + secrets sa/sb):
//   - alice  = principals[0], granted secrets.read scoped ONLY to projectA, owns sa.
//   - bob    = principals[1], granted secrets.read scoped ONLY to projectB, owns sb.
// Neither is a global admin; neither has any grant at the other's scope. Grants are FIXED
// (never cross-project — that is the boundary under test), so there is no per-iteration
// grant churn to model.
//
// All oracles are deny-direction / equality only (never "must succeed"), so none can
// false-positive:
//   - CONFIDENTIALITY: a cross-tenant read is never 200 and its body never contains the
//     target secret's plaintext.
//   - NO ENUMERATION: a principal's list never contains the other tenant's project/secret.
//   - NO EXISTENCE ORACLE: a cross-tenant by-id GET of the other tenant's REAL secret id and
//     of a never-existed id are indistinguishable (same status, both non-2xx). This asserts
//     keyorix's ADR-096 "403-for-both" anti-enumeration convention; a divergence is an
//     existence-oracle leak.
//   - NO CACHE BLEED: after alice reads her own secret, an immediately-following bob read of
//     the SAME ref returns bob's (deny) decision, not a cached alice 200.
// Positive controls (keep it non-vacuous): each principal CAN read their own secret — asserted
// every iteration — so a harness that denied everything could not pass.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func FuzzMultiTenantIsolation(f *testing.F) {
	w := buildAPIFuzzWorld(f)
	f.Cleanup(i18n.ResetForTesting)
	ctx := f.Context()

	alice, bob := w.principals[0], w.principals[1]
	if alice.token == "" || bob.token == "" {
		f.Fatalf("isolation harness needs two logged-in principals (alice=%q bob=%q)", alice.token, bob.token)
	}
	// Fixed, single-project grants — alice→projA, bob→projB. Never cross-project.
	if err := w.c.AssignUserRole(ctx, 0, alice.id, w.readerRole, core.Scope{ProjectID: w.projAID}, false); err != nil {
		f.Fatalf("grant alice@projA: %v", err)
	}
	if err := w.c.AssignUserRole(ctx, 0, bob.id, w.readerRole, core.Scope{ProjectID: w.projBID}, false); err != nil {
		f.Fatalf("grant bob@projB: %v", err)
	}

	// Resolve the real secret node ids (needed for the by-id existence-oracle check) + a
	// never-existed id well above any real row.
	var na, nb models.SecretNode
	if e := w.db.Where("name = ? AND project_id = ?", "sa", w.projAID).First(&na).Error; e != nil {
		f.Fatalf("lookup sa id: %v", e)
	}
	if e := w.db.Where("name = ? AND project_id = ?", "sb", w.projBID).First(&nb).Error; e != nil {
		f.Fatalf("lookup sb id: %v", e)
	}
	idA, idB := na.ID, nb.ID
	fakeID := idA + idB + 4242424

	// tenant bundles: everything about one principal's own tenant.
	type tenant struct {
		tok, ref, val, proj string
		id                  uint
	}
	tA := tenant{tok: alice.token, ref: w.refA, val: w.valA, proj: "proja", id: idA}
	tB := tenant{tok: bob.token, ref: w.refB, val: w.valB, proj: "projb", id: idB}

	do := func(tok, method, target string) (int, string) {
		req := httptest.NewRequest(method, target, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	f.Add([]byte{0x00})             // alice read-ref own
	f.Add([]byte{0x08})             // alice read-ref other (cross-tenant)
	f.Add([]byte{0x0a})             // alice read-id other
	f.Add([]byte{0x04})             // alice list
	f.Add([]byte{0x09, 0x0b, 0x0c}) // bob cross reads + list
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		if len(program) > 64 {
			program = program[:64]
		}

		for _, b := range program {
			actor, other := tA, tB
			if b&1 == 1 {
				actor, other = tB, tA
			}
			targetOther := (b>>3)&1 == 1
			tgt := actor
			if targetOther {
				tgt = other
			}

			switch (b >> 1) & 3 {
			case 0: // read-by-ref
				code, body := do(actor.tok, http.MethodGet, "/api/v1/secrets/value?ref="+tgt.ref)
				if targetOther {
					if code == http.StatusOK {
						t.Fatalf("ISOLATION: cross-tenant read-ref of %q returned 200", tgt.ref)
					}
					if strings.Contains(body, tgt.val) {
						t.Fatalf("PLAINTEXT LEAK: cross-tenant read-ref of %q (code=%d) body contains the secret value", tgt.ref, code)
					}
				}
			case 1: // read-by-id + existence-oracle differential
				if targetOther {
					cReal, bReal := do(actor.tok, http.MethodGet, "/api/v1/secrets/"+strconv.FormatUint(uint64(tgt.id), 10))
					cFake, _ := do(actor.tok, http.MethodGet, "/api/v1/secrets/"+strconv.FormatUint(uint64(fakeID), 10))
					if cReal == http.StatusOK {
						t.Fatalf("ISOLATION: cross-tenant read-id of real id %d returned 200", tgt.id)
					}
					if strings.Contains(bReal, tgt.val) {
						t.Fatalf("PLAINTEXT LEAK: cross-tenant read-id of %d body contains the secret value", tgt.id)
					}
					// Existence oracle: real-forbidden vs never-existed must be indistinguishable
					// (ADR-096 403-for-both). Only meaningful when both are non-2xx.
					if cReal < 200 || cReal >= 300 {
						if cReal != cFake {
							t.Fatalf("EXISTENCE ORACLE: cross-tenant by-id of a REAL other-tenant secret (code=%d) differs from a never-existed id (code=%d) — leaks existence", cReal, cFake)
						}
					}
				}
			case 2: // list — no enumeration of the other tenant
				code, body := do(actor.tok, http.MethodGet, "/api/v1/secrets/")
				if code == http.StatusOK {
					if strings.Contains(body, other.proj) {
						t.Fatalf("ENUMERATION: %s's secret list contains the other tenant's project %q", actor.proj, other.proj)
					}
					if strings.Contains(body, other.val) {
						t.Fatalf("PLAINTEXT LEAK: %s's secret list contains the other tenant's value", actor.proj)
					}
				}
			case 3: // by-name metadata lookup, cross-tenant
				if targetOther {
					q := fmt.Sprintf("/api/v1/secrets/by-name?project_id=%d&name=%s", func() uint {
						if tgt.proj == "proja" {
							return w.projAID
						}
						return w.projBID
					}(), strings.TrimPrefix(tgt.ref[strings.LastIndex(tgt.ref, "/")+1:], ""))
					code, body := do(actor.tok, http.MethodGet, q)
					if code == http.StatusOK && strings.Contains(body, tgt.val) {
						t.Fatalf("PLAINTEXT LEAK: cross-tenant by-name of %q returned the value", tgt.ref)
					}
				}
			}
		}

		// NO CACHE BLEED: alice reads her own secret (200), then bob reads the SAME ref and
		// must be denied — the identity cache holds identity, not authz.
		if c1, _ := do(tA.tok, http.MethodGet, "/api/v1/secrets/value?ref="+tA.ref); c1 == http.StatusOK {
			if c2, b2 := do(tB.tok, http.MethodGet, "/api/v1/secrets/value?ref="+tA.ref); c2 == http.StatusOK || strings.Contains(b2, tA.val) {
				t.Fatalf("CACHE BLEED: bob read alice's ref %q right after alice (code=%d)", tA.ref, c2)
			}
		}

		// POSITIVE CONTROLS (non-vacuous): each principal can read their own secret.
		for _, own := range []tenant{tA, tB} {
			code, body := do(own.tok, http.MethodGet, "/api/v1/secrets/value?ref="+own.ref)
			if code == http.StatusOK && !strings.Contains(body, own.val) {
				t.Fatalf("POSITIVE-CONTROL: own read of %q was 200 but body lacks the value", own.ref)
			}
			if code != http.StatusOK {
				t.Fatalf("POSITIVE-CONTROL: own read of %q denied (code=%d) — grant/setup regression makes the isolation oracles vacuous", own.ref, code)
			}
		}
	})
}
