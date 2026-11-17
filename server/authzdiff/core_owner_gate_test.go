package authzdiff

import (
	"slices"
	"testing"
)

// TestCoreOwnerWithoutPermissionIsRefused: the harness's viewer-owned secret
// (arg 1, project A) is owned by the viewer, whose role grants neither
// secrets.write nor secrets.delete. REST and gRPC refuse the viewer's update
// and delete at the per-secret gate; core's UpdateSecretWithPermissionCheck /
// DeleteSecretWithPermissionCheck must refuse them too, typed
// (ErrPermissionDenied), instead of letting ownership alone authorize the
// mutation (#4160, former waiver known-03).
//
// Not covered here: an owner who does hold the permission (the admin positive
// control of every sweep covers allow), and other ops' owner rules.
func TestCoreOwnerWithoutPermissionIsRefused(t *testing.T) {
	specs := withDerived(t, ops())
	for _, name := range []string{"secret.update", "secret.delete"} {
		i := slices.IndexFunc(specs, func(s opSpec) bool { return s.name == name })
		if i < 0 {
			t.Fatalf("op %s not defined", name)
		}
		spec := specs[i]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := runCase(t, spec, caseKey{Op: name, Principal: pkViewer, Target: tA.String(), Arg: 1, variation: defaultVariation}, tA)
			rest, grpc := r.Legs[layerREST], r.Legs[layerGRPC]
			if rest == nil || rest.NA != "" || rest.Outcome != Denied || grpc == nil || grpc.NA != "" || grpc.Outcome != Denied {
				t.Fatalf("precondition: REST and gRPC must refuse the viewer-owner: %s", r.line())
			}
			if core := r.Legs[layerCore]; core == nil || core.NA != "" || core.Outcome != Denied || core.Detail != "ErrPermissionDenied" {
				t.Errorf("core must refuse the viewer-owner with ErrPermissionDenied, as the transports do: %s", r.line())
			}
		})
	}
}
