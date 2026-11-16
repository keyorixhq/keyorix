package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// V5b area 1: environment-scoped grants.
//
// A role grant carries an environment_id; a grant with environment_id E != 0
// authorizes only checks whose target environment is E (and only while that
// environment is live), while environment_id 0 is the all-environments
// wildcard. The reference model expresses this independently (model_test.go:
// grant.envID, requirement.env, holds' env match + environmentLive) — it reads
// the three grant tables directly and never calls core authorization.
//
// The vehicle is a secret VALUE-READ driven in two environments of the SAME
// project: arg 0 reads the prod secret (perProject.sx.plainID, environment
// perProject.envID), arg 1 reads the staging2 secret (sx.envAltSecretID,
// environment sx.targetEnvID). Both are admin-owned with no ACL/share for any
// probed principal, so each layer's decision is the RBAC check at the secret's
// own {project, environment} scope alone — exactly the scope core builds in
// AuthorizeSecretAction (Scope{secret.ProjectID, secret.EnvironmentID}).
//
// The custom principal is additionally offered an environment-scoped grant
// (envVariations, sweep_test.go: the "<proj>@prod"/"<proj>@stg" scope tokens):
// secrets.read granted only in prod, or only in staging2. Reading the OTHER
// environment is then refused by every layer and by the model — the
// cross-environment denial that the env-scope plant (plants_test.go:
// env-scope-clause-removed) flips to a core/REST over-allow the model catches.
//
// coreEnforced: GetSecretForValueRead is a real core gate (matrix
// core_refusal != "none"), so all three legs take part in Oracle 1 and each is
// checked against the model (Oracle 2). A MACHINE actor reaches core through a
// non-checking path for value read (errNotAuthzLayer), identical to the other
// value-read bindings, so its core leg is recorded n/a.
//
// What this binding does NOT verify: it exercises the read action only, at the
// grant level — it does not model per-secret ACL/share elevation across
// environments (those secrets carry none), nor environment-scoped grants on
// the GROUP or MACHINE route beyond the one sweep/fuzz offers (the custom
// principal's user-route grant is the red-proof carrier), nor write/delete/list
// /export as distinct routes (the authorization scope is the same
// {project, environment} for all of them — the model rule is route-independent;
// only the read route is bound as the representative).
func v5bOps() []opSpec {
	return []opSpec{
		{
			name: "secret.read.env", row: "GetSecretForValueRead", targets: projTargets, envScoped: true,
			req: func(fx *fixtures, t tgt, a byte) requirement {
				_, env := envSecret(fx, t, a)
				return requirement{perms: []string{"secrets.read"}, scope: pid(fx, t), env: env}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, a byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				id, _ := envSecret(lg.fx, t, a)
				ps, err := lg.c.GetSecretForValueRead(ctx, id, p.userID)
				if err != nil {
					return err
				}
				_, err = lg.c.GetPermittedSecretValue(ctx, ps)
				return err
			},
			rest: func(fx *fixtures, t tgt, a byte) restReq {
				id, _ := envSecret(fx, t, a)
				return restReq{http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, a byte) error {
				id, _ := envSecret(lg.fx, t, a)
				_, err := pb.NewSecretServiceClient(lg.conn).GetSecretValue(ctx, &pb.GetSecretRequest{Id: uint32(id), IncludeValue: true})
				return err
			},
		},
	}
}

// envSecret selects the per-(target, arg) secret the environment-scoped read op
// acts on, and returns its environment id:
//
//	arg 0 -> prod secret (sx.plainID),    environment perProject.envID
//	arg 1 -> staging2 secret (sx.envAltSecretID), environment sx.targetEnvID
func envSecret(fx *fixtures, t tgt, a byte) (id, env uint) {
	pp := fx.proj(byte(t))
	if a%2 == 1 {
		return pp.sx.envAltSecretID, pp.sx.targetEnvID
	}
	return pp.sx.plainID, pp.envID
}

// isV5bOp reports whether name is one of the V5b env-scoped bindings.
func isV5bOp(name string) bool {
	for _, s := range v5bOps() {
		if s.name == name {
			return true
		}
	}
	return false
}
