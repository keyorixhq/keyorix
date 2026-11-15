package authzdiff

import (
	"net/http"
	"regexp"
	"slices"
	"testing"
)

// routeGateFamilies are the REST route families whose mutating ops' core entry
// points enforce the route group's gate permission themselves (#4161, the
// former authzdiff waiver known-04): the per-secret secrets.write, the /roles
// group's roles.read, the /groups and /users groups' users.read, and the
// route's own permission. A family's population is DERIVED: every bound,
// core-enforced, non-GET op whose REST request (first target, arg 0) matches
// the family's path. A new op on one of these routes is therefore checked by
// TestCoreEnforcesRouteGate without being listed anywhere.
var routeGateFamilies = []struct {
	name string
	path *regexp.Regexp
}{
	{"secrets", regexp.MustCompile(`^/api/v1/secrets/\d+/(auto-rotate|rotate|rollback|copy|move|tags|description)$`)},
	{"shares", regexp.MustCompile(`^/api/v1/shares/\d+$`)},
	{"environments", regexp.MustCompile(`^/api/v1/projects/\d+/environments/\d+/(clone|copy-secrets)$`)},
	{"roles", regexp.MustCompile(`^/api/v1/roles(/|$)`)},
	{"users", regexp.MustCompile(`^/api/v1/users(/\d+/roles)?$`)},
	{"groups", regexp.MustCompile(`^/api/v1/groups(/|$)`)},
	{"projects", regexp.MustCompile(`^/api/v1/projects/\d+/restore$`)},
	{"invitations", regexp.MustCompile(`^/api/v1/invitations$`)},
	{"approvals", regexp.MustCompile(`^/api/v1/access-requests/bulk-approve$`)},
}

// knownRouteGateOps are the ops #4161 listed (every op the known-04 waiver
// matched on main before the fix). TestRouteGateFamiliesCoverKnownOps keeps the
// derived families from shrinking below them.
var knownRouteGateOps = []string{
	"secret.autorotate", "secret.rotate", "secret.rollback", "secret.copy", "secret.move", "secret.tags", "secret.description",
	"share.revoke",
	"env.clone", "env.copy.secrets",
	"role.update", "role.delete", "role.perm.add",
	"user.create", "user.create.assign", "user.roles.set",
	"group.restore", "group.role.assign", "group.member.add",
	"project.restore",
	"invitation.global",
	"accessrequest.bulk.approve",
}

// routeGateOps returns the derived family population, op name -> family.
func routeGateOps(tb testing.TB) (map[string]string, []opSpec) {
	tb.Helper()
	_, fx := template(tb)
	got := map[string]string{}
	var specs []opSpec
	for _, spec := range withDerived(tb, ops()) {
		if !spec.coreEnforced || spec.core == nil || spec.rest == nil {
			continue
		}
		rr := spec.rest(fx, spec.targets[0], 0)
		if rr.method == http.MethodGet {
			continue
		}
		for _, f := range routeGateFamilies {
			if f.path.MatchString(rr.path) {
				got[spec.name] = f.name
				specs = append(specs, spec)
				break
			}
		}
	}
	return got, specs
}

// TestRouteGateFamiliesCoverKnownOps: every op #4161 named is in a derived
// family (a family regexp that stops matching one fails here, not silently).
func TestRouteGateFamiliesCoverKnownOps(t *testing.T) {
	got, _ := routeGateOps(t)
	for _, op := range knownRouteGateOps {
		if _, ok := got[op]; !ok {
			t.Errorf("op %s is not in any route-gate family (routeGateFamilies)", op)
		}
	}
	t.Logf("route-gate families: %d ops", len(got))
}

// TestCoreEnforcesRouteGate: for every op of the route-gate families, core
// refuses wherever REST refuses, gRPC refuses or has no RPC, and the model
// denies — the shape the known-04 waiver used to absorb (#4161). Principals:
// the named ones (except the system actor and the suspended account, which
// TestCoreRefusesSuspendedActor and ID-1 cover), and for each permission p of
// the op's requirement a custom role, a group-granted custom role and a machine
// holding everything else at the op's own scope (R \ {p}): the principals a
// core entry point that does not check p lets through.
//
// Not covered: the other masks and scopes of the full sweep (the strict
// AUTHZDIFF_SWEEP run covers those), and ops whose core method does no authz
// at all (coreEnforced false, intended difference ID-2).
func TestCoreEnforcesRouteGate(t *testing.T) {
	_, specs := routeGateOps(t)
	for _, spec := range specs {
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()
			probe := newLeg(t, layerCore)
			defer probe.close()
			for _, tg := range spec.targets {
				own := tg.String()
				machineScope := own
				if tg == tGlobal {
					machineScope = "A"
				}
				for _, arg := range argsFor(spec) {
					if spec.invalidArg != nil && spec.invalidArg(tg, arg) {
						continue
					}
					var cases []caseKey
					for _, pk := range namedPrincipalKinds {
						if pk == pkActor0 || pk == pkSuspended {
							continue
						}
						cases = append(cases, caseKey{Principal: pk, variation: defaultVariation})
					}
					r := maskOf(requirementPerms(probe, spec, tg, arg))
					for i := range customPermUniverse {
						bit := uint16(1) << i
						if r&bit == 0 {
							continue
						}
						cases = append(cases,
							caseKey{Principal: pkCustom, variation: variation{r &^ bit, "user", own}},
							caseKey{Principal: pkCustom, variation: variation{r &^ bit, "group", own}},
							caseKey{Principal: pkMachine, variation: variation{r &^ bit, "machine", machineScope}})
					}
					for _, k := range cases {
						k.Op, k.Target, k.Arg = spec.name, own, arg
						res := runCase(t, spec, k, tg)
						if coreAllowsWhatTransportsRefuse(res) {
							t.Errorf("core allows what the route gate refuses: %s", res.line())
						}
					}
				}
			}
		})
	}
}

// coreAllowsWhatTransportsRefuse is the known-04 shape: core allows, REST
// denies, gRPC denies or has no RPC, and the model denies.
func coreAllowsWhatTransportsRefuse(r *caseResult) bool {
	core, rest, grpc := r.Legs[layerCore], r.Legs[layerREST], r.Legs[layerGRPC]
	is := func(lo *legOutcome, o Outcome) bool { return lo != nil && lo.NA == "" && lo.Outcome == o }
	grpcDeniedOrNA := grpc == nil || grpc.NA != "" || grpc.Outcome == Denied
	return is(core, Allowed) && is(rest, Denied) && grpcDeniedOrNA && slices.Contains([]Outcome{Denied, ModelNA}, r.Model)
}
