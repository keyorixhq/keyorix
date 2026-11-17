package authzdiff

import (
	"slices"
	"testing"
)

// TestCoreRefusalsAreTyped: on the ops of the former waivers known-08 (#4162:
// machine actors on human-only secret/request ops) and known-09 (#4163:
// secret.copy, membership.transition, share.update, break-glass), a core
// refusal is typed (ErrPermissionDenied), and a transport that refuses answers
// it as a refusal: REST 401/403 (never 400 or 500), gRPC PermissionDenied or
// Unauthenticated (never InvalidArgument or Internal). Each op as the machine,
// viewer, no-role, restricted-PAT and default custom-role principals, first
// target, every arg.
//
// Not covered here: whether a machine SHOULD be allowed any of these ops (the
// model allows a few, a product decision reported as NEEDS ADMIN); ops outside
// this list, which the full strict sweep covers (an untyped core error is no
// longer waived anywhere).
func TestCoreRefusalsAreTyped(t *testing.T) {
	names := []string{"secret.acl.grant", "secret.share", "accessrequest.create", "secret.certificate", "secret.tags",
		"secret.description", "secret.move", "secret.copy", "secret.extend.expiring",
		"membership.transition", "share.update", "breakglass.activate"}
	principals := []principalKind{pkMachine, pkViewer, pkNone, pkPAT, pkCustom}
	specs := withDerived(t, ops())
	for _, name := range names {
		i := slices.IndexFunc(specs, func(s opSpec) bool { return s.name == name })
		if i < 0 {
			t.Fatalf("op %s not defined", name)
		}
		spec := specs[i]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tg := spec.targets[0]
			for _, arg := range argsFor(spec) {
				if spec.invalidArg != nil && spec.invalidArg(tg, arg) {
					continue
				}
				for _, pk := range principals {
					r := runCase(t, spec, caseKey{Op: name, Principal: pk, Target: tg.String(), Arg: arg, variation: defaultVariation}, tg)
					core, rest, grpc := r.Legs[layerCore], r.Legs[layerREST], r.Legs[layerGRPC]
					if core == nil || core.NA != "" || core.Outcome == Allowed {
						continue
					}
					if core.Detail == "untyped-error" {
						t.Errorf("core refused with an untyped error: %s", r.line())
						continue
					}
					if rest != nil && rest.NA == "" && rest.Outcome == Other && (rest.Detail == "Bad Request" || rest.Detail == "Internal Server Error") {
						t.Errorf("REST answered a typed core refusal %s: %s", rest.Detail, r.line())
					}
					if grpc != nil && grpc.NA == "" && grpc.Outcome == Other && (grpc.Detail == "InvalidArgument" || grpc.Detail == "Internal") {
						t.Errorf("gRPC answered a typed core refusal %s: %s", grpc.Detail, r.line())
					}
				}
			}
		})
	}
}
