// lookup_verdict_secret_mutations_test.go — FIX-ERRMAP-STRUCT-1 item 3 (#3873).
//
// The five REST secret mutations that authorize inside core (PUT/DELETE
// /api/v1/secrets/{id}, PATCH .../description, PUT .../tags, POST .../move) answered a
// fault on their in-core permission lookup (ResolveUserPermissionAt, second call: the
// route gate's own lookup is the first) 403, and stood as the last ten #3873 oracle (h)
// tolerance rows. They now answer 503 through the shared classifier with the
// permission-lookup fault recorder; this drives every (op, kind) through the real
// harness and the whole oracle, with no tolerance, so the rows cannot come back
// silently.
package faultops

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestLookupVerdict_SecretMutationPermissionFaultIs503(t *testing.T) {
	ops := []string{
		"REST PUT /api/v1/secrets/{id}",
		"REST DELETE /api/v1/secrets/{id}",
		"REST PATCH /api/v1/secrets/{id}/description",
		"REST PUT /api/v1/secrets/{id}/tags",
		"REST POST /api/v1/secrets/{id}/move",
	}
	for _, op := range ops {
		for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
			t.Run(op+"/"+kind.String(), func(t *testing.T) {
				in, outcome, reason := driveFaultCase(t, op, "ResolveUserPermissionAt", 2, kind)
				if outcome != driveObserved {
					t.Fatalf("could not be driven (%s: %s)", outcome, reason)
				}
				if !strings.HasPrefix(in.result.Detail, "HTTP 503") {
					t.Fatalf("a permission-lookup fault inside core must answer 503, got %q", in.result.Detail)
				}
				if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) > 0 {
					t.Fatalf("the oracle reports: %v", f)
				}
			})
		}
	}
}
