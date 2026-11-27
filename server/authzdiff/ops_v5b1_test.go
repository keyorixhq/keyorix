package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// V5B1 ops (batch B1 of the authzdiff model extension, EXTENSION-PLAN.md §6):
// secret-read conditions and secret-scoped approval. This file holds the rules
// that need no new reference-model field — a binding of the existing
// requirement machinery to a previously-uncovered route.
//
// # secret.classify (plan rule 7 "classify-actor")
//
// PATCH /api/v1/secrets/{id}/classification (op #7 in the ranking):
//
//	Route:   r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id", core.SecretActionClassify)).
//	           Patch("/{id}/classification", secretHandler.ClassifySecret)  (server/http/router.go:812)
//	Gate:    permSecretsWrite, resolved per-secret (RequireScopedSecretPermission) — the SAME gate the
//	         covered secret.update op uses (router.go:811, SecretActionUpdate). So its authorization is
//	         exactly secret.update's: secrets.write at the secret's project scope, plus the per-secret
//	         ACL/share/owner terms the model records as n/a for args 1-3.
//	Core:    ClassifySecret(actorID, username, secretID, level) performs NO authorization of its own
//	         (internal/core/classification.go:54; the only core check is that DOWNGRADING a "restricted"
//	         secret re-runs the read gate, classification.go:80 — not reached here: the fixture secrets are
//	         default-classified and the op raises the level). matrix.json records core_refusal="none", so
//	         coreEnforced=false → the core leg is recorded but excluded from both oracles (ID-2,
//	         transport-enforced). The route gate is the sole enforcement point.
//	Model:   requirement{perms:[secrets.write], scope: project} with secretArgs — identical to secret.update.
//	         Oracle 2 checks arg 0 (admin-owned, no share/ACL for a probed principal) against the model;
//	         args 1-3 are the owner/share/ACL fixtures, recorded ModelNA (outside the model's domain).
//
// Product evidence this binding encodes (verified against the tree, not the plan):
//   - The route gate is permSecretsWrite, NOT a project-scoped RequireScopedPermission:
//     RequireScopedSecretPermission is a per-secret gate (ACL + share + owner + role), the identical
//     shape secret.update already carries. The plan's rule-7 phrasing "at the secret's own environment"
//     describes AuthorizeSecretAction's scope derivation; the route gate itself resolves the project
//     from the secret and checks secrets.write there — the same project scope secret.update models with
//     requirement.scope and no requirement.env. Recorded as a plan/product note in the report.
//
// What this oracle does NOT verify:
//   - It does not exercise classification DOWNGRADE from "restricted" (classification.go:80's re-run of
//     the read gate): the fixtures carry no restricted secret, and the op always raises the level.
//   - It does not check that the chosen level actually persisted — only that the layer allowed/denied the
//     call; a 2xx is taken as Allowed (no restOK filter, like secret.update).
//   - Per-secret ACL/share/owner authorization for args 1-3 is Oracle-1 only (ModelNA), unchanged from
//     every other secretArgs op.
//   - It says nothing about gRPC: there is no ClassifySecret RPC (ID-3, no gRPC leg).

func v5b1Ops() []opSpec {
	return []opSpec{
		{
			name: "secret.classify", row: "ClassifySecret", targets: projTargets, secretArgs: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				return requirement{perms: []string{"secrets.write"}, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				// Raise to "confidential": a valid level that is NOT "restricted", so
				// the downgrade re-gate (classification.go:80) is never reached.
				_, err := lg.c.ClassifySecret(ctx, p.userID, p.username, sec(lg.fx, t, a).id, core.ClassificationConfidential)
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				return restReq{http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/classification", sec(fx, t, a).id),
					map[string]any{"classification": core.ClassificationConfidential}}
			},
			// No gRPC leg: there is no ClassifySecret RPC (matrix has no grpc row for it).
		},
	}
}

// isV5b1Op reports whether name is one of the V5B1 bindings.
func isV5b1Op(name string) bool {
	for _, s := range v5b1Ops() {
		if s.name == name {
			return true
		}
	}
	return false
}
