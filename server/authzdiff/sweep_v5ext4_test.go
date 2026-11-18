package authzdiff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	httpserver "github.com/keyorixhq/keyorix/server/http"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// TestV5ext4StrictSweep is a deterministic, env-free strict check over the
// V5EXT4 bindings (ops_v5ext4_test.go): bulk.rotate and mfa.stepup.
//
// bulk.rotate:
//   Router gate: secrets.write @ project. Core: no auth check at all
//   (errNotAuthzLayer for all principals). No gRPC surface.
//   Positive control: admin → 200+triggered=[secretID] (AutoRotate=true in fixture).
//
// mfa.stepup:
//   No RBAC gate. Core: VerifyMFAStepUp checks user.MFAEnabled (core_refusal=none →
//   coreEnforced=false). Positive control: pkMFAUser (the only MFA-enrolled principal).
//   Named principals include pkMFAUser (world_test.go V5EXT4 seed).
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext4StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT4 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext4Op(spec.name) {
			continue
		}
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			for _, tg := range spec.targets {
				for _, arg := range argsFor(spec) {
					if spec.invalidArg != nil && spec.invalidArg(tg, arg) {
						continue
					}
					run := func(pk principalKind, v variation) {
						k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg, variation: v}
						r := runCase(t, spec, k, tg)
						sink.write(r)
						tally.add(t, r)
					}
					for _, pk := range namedPrincipalKinds {
						run(pk, defaultVariation)
					}
					for _, cv := range curatedV5ext4Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT4 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT4 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT4 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 5 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedV5ext4Variations: gate-boundary cases for a V5EXT4 op.
//
// bulk.rotate: secrets.write @ project; same curated shapes as V5EXT3 write ops
// (holds/lacks via user; holds only at other; via group; machine holds/lacks).
// Machine+holds is kept (no machine-specific rejection in BulkRotateSecrets, unlike
// bulk.rename/suspend/resume; core returns errNotAuthzLayer for all actors).
//
// mfa.stepup: no RBAC permission; no curated variations (the only boundary is
// MFA enrolment, which is a fixture property of pkMFAUser — a named principal).
func curatedV5ext4Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	if spec.name != "bulk.rotate" {
		return nil
	}
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	gatePerm := maskOf([]string{"secrets.write"})
	have := maskOf([]string{"secrets.write"})
	return []pv{
		{pkCustom, variation{Mask: have, Route: "user", Scope: here}},
		{pkCustom, variation{Mask: allPerms &^ gatePerm, Route: "user", Scope: here}},
		{pkCustom, variation{Mask: have, Route: "user", Scope: other}},
		{pkCustom, variation{Mask: have, Route: "group", Scope: here}},
		{pkMachine, variation{Mask: allPerms &^ gatePerm, Route: "machine", Scope: here}},
		{pkMachine, variation{Mask: have, Route: "machine", Scope: here}},
	}
}

// TestBulkRotateRouterGatePresent verifies the bulk-rotate router gate is
// registered in server/http/router.go exactly as the authzdiff harness expects.
//
// Differential plants cannot reliably detect gate removal for bulk-rotate: the
// core function has no authorization check (errNotAuthzLayer for all actors), so
// an unauthorized caller reaching core directly would succeed. The router gate is
// the ONLY authorization layer. This structural check ensures it cannot be removed
// without an immediate test failure.
//
// Red/green proof:
//   - RED: remove the anchor from router.go → this test fails.
//   - GREEN: tree as committed → this test passes.
func TestBulkRotateRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/bulk-rotate", secretHandler.BulkRotateSecrets)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("bulk-rotate router gate anchor found %d times (want 1): %q", n, anchor)
	}
}

// TestSCIMStrictSweep is a deterministic, standalone strict check over the 8 SCIM
// endpoints (POST/PUT/PATCH/DELETE for Users and Groups).
//
// Unlike the standard sweep, SCIM routes require a custom router built with
// cfg.SCIM.Enabled=true. Each case gets its own fresh SCIM-enabled router leg
// (cloned from the template DB, same pattern as newLeg but with SCIM config).
//
// Two principals are probed:
//   - pkSCIM: the configured SCIM bearer token → allowed (2xx).
//   - pkNone (no Authorization header): 401 → denied.
//
// Rate-limiter note: each pkNone probe burns one token from the process-global
// per-IP token-auth failure budget (burst=10). The budget is reset before the sweep
// to avoid accumulation from earlier tests in the binary. With 8 ops × 1 pkNone
// probe each = 8 burns; well within the burst.
//
// What this oracle does NOT verify:
//   - IdP-managed-user guard: ReplaceUser/PatchUser/DeleteUser refuse a user
//     whose ExternalID is empty (non-SCIM-managed). The fixture pre-provisions a
//     SCIM user (ExternalID="ext-scim-seed-1"), so the guard never fires.
//   - Privilege-ceiling on group membership grants (SCIM groups map to Keyorix
//     groups; granting a high-privilege group to an IdP user is not modelled here).
//   - Partial failures in PatchUser/PatchGroup.
func TestSCIMStrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("SCIM strict sweep drives real REST legs; skipped under -short")
	}
	// Reset the global per-IP invalid-token limiter so accumulated failures from
	// other tests don't exhaust our budget (8 pkNone probes, burst=10).
	middleware.ResetTokenAuthFailureLimiterForTest()

	const scimTok = "test-scim-bearer-token-32ch-sweep" // ≥20 chars (MinSCIMTokenLength)

	b, fx := template(t)

	type scimCase struct {
		name   string
		method string
		path   func() string
		body   func() any
		okCode int // expected success HTTP status
	}

	scimUserPath := fmt.Sprintf("/scim/v2/Users/%d", fx.scimUserID)
	scimGroupPath := fmt.Sprintf("/scim/v2/Groups/%d", fx.scimGroupID)

	// PatchUser body: replace displayName (non-active-toggle patch, always succeeds
	// on a SCIM-managed user regardless of active state).
	patchUserBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "Replace", "path": "displayName", "value": "Updated-By-SCIM-Sweep"},
		},
	}
	// PatchGroup body: rename (safe mutation on the pre-seeded group).
	patchGroupBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "Replace", "path": "displayName", "value": "scim-sweep-renamed-group"},
		},
	}
	// ReplaceUser body: minimal valid payload (userName required).
	replaceUserBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "scim-seed@example.invalid",
		"displayName": "SCIM Seed User Updated",
		"active":      true,
	}
	// ReplaceGroup body: keep existing member set.
	replaceGroupBody := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "scim-seed-group-updated",
		"members":     []map[string]any{{"value": fmt.Sprintf("%d", fx.scimUserID)}},
	}

	cases := []scimCase{
		{
			name: "scim.user.create", method: http.MethodPost,
			path:   func() string { return "/scim/v2/Users" },
			body:   func() any { return map[string]any{"userName": "scim-new@example.invalid", "externalId": "ext-scim-new-sweep-1"} },
			okCode: http.StatusCreated,
		},
		{
			name: "scim.user.replace", method: http.MethodPut,
			path: func() string { return scimUserPath }, body: func() any { return replaceUserBody },
			okCode: http.StatusOK,
		},
		{
			name: "scim.user.patch", method: http.MethodPatch,
			path: func() string { return scimUserPath }, body: func() any { return patchUserBody },
			okCode: http.StatusOK,
		},
		{
			name: "scim.user.delete", method: http.MethodDelete,
			path:   func() string { return scimUserPath },
			body:   nil,
			okCode: http.StatusNoContent,
		},
		{
			name: "scim.group.create", method: http.MethodPost,
			path:   func() string { return "/scim/v2/Groups" },
			body:   func() any { return map[string]any{"displayName": "scim-new-group-sweep", "members": []map[string]any{{"value": fmt.Sprintf("%d", fx.scimUserID)}}} },
			okCode: http.StatusCreated,
		},
		{
			name: "scim.group.replace", method: http.MethodPut,
			path: func() string { return scimGroupPath }, body: func() any { return replaceGroupBody },
			okCode: http.StatusOK,
		},
		{
			name: "scim.group.patch", method: http.MethodPatch,
			path: func() string { return scimGroupPath }, body: func() any { return patchGroupBody },
			okCode: http.StatusOK,
		},
		{
			name: "scim.group.delete", method: http.MethodDelete,
			path:   func() string { return scimGroupPath },
			body:   nil,
			okCode: http.StatusNoContent,
		},
	}

	type result struct {
		name, principal string
		status          int
		body            string
	}
	var fails []result

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Build a fresh SCIM-enabled leg for each case. Each leg gets its own
			// copy of the template DB (byte copy). routerMu serialises router
			// construction because NewRouter sets package-level handler globals.
			db := fuzzworld.OpenSQLiteFromImage(t, b)
			ls := store.NewLocalStorage(db)
			co := newCore(ls)
			routerMu.Lock()
			r, err := httpserver.NewRouter(&config.Config{
				SCIM: config.SCIMConfig{Enabled: true, Token: scimTok},
			}, co)
			routerMu.Unlock()
			if err != nil {
				t.Fatalf("SCIM router: %v", err)
			}
			defer func() {
				if s, e := db.DB(); e == nil {
					_ = s.Close()
				}
			}()

			doRequest := func(tok string, expectOK bool) {
				var bodyBuf bytes.Buffer
				if c.body != nil {
					_ = json.NewEncoder(&bodyBuf).Encode(c.body())
				}
				req := httptest.NewRequest(c.method, c.path(), &bodyBuf)
				if c.body != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				if tok != "" {
					req.Header.Set("Authorization", "Bearer "+tok)
				}
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, req)
				status := rec.Code

				if expectOK {
					if status != c.okCode {
						fails = append(fails, result{c.name, "pkSCIM", status, rec.Body.String()})
						t.Errorf("%s pkSCIM: want %d got %d body=%s", c.name, c.okCode, status, rec.Body.String())
					}
				} else {
					// No/wrong token → 401 (rate allowed) or 429 (rate exhausted).
					if status != http.StatusUnauthorized && status != http.StatusTooManyRequests {
						fails = append(fails, result{c.name, "pkNone", status, rec.Body.String()})
						t.Errorf("%s pkNone: want 401 or 429 got %d body=%s", c.name, status, rec.Body.String())
					}
				}
			}

			// Valid SCIM token → allowed.
			doRequest(scimTok, true)
			// No token → denied (401).
			doRequest("", false)
		})
	}

	t.Logf("SCIM sweep: %d operations, %d failures", len(cases), len(fails))
	if len(fails) > 0 {
		t.Errorf("SCIM sweep had %d failures (see above)", len(fails))
	}
}

// TestSCIMRouterGatePresent verifies the SCIM token middleware is wired on every
// SCIM mutating route in server/http/router.go.
//
// The SCIMToken middleware is the ONLY authorization layer for SCIM routes.
// Without it, any unauthenticated caller could provision/deprovision users.
//
// Red/green proof:
//   - RED: remove the r.Use(customMiddleware.SCIMToken(...)) line → test fails.
//   - GREEN: tree as committed → test passes (anchor found exactly once).
func TestSCIMRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.Use(customMiddleware.SCIMToken(cfg.SCIM.GetToken()))`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("SCIM token middleware anchor found %d times (want 1): %q", n, anchor)
	}
}
