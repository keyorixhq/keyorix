package services

// POSTURE-CONSUMERS-NOV-1 item 1: every field the core emergency-access posture
// returns over REST must be declared in the gRPC posture message, or be named
// in knownUndeclaredEmergencyAccessFields with the reason. A field added to
// core.EmergencyAccessPosture (the REST body) that nobody added to the proto
// leaves gRPC and generated-client consumers blind to it, which is how
// degraded_activations stayed invisible after POSTURE-DEGRADED-NOV-1.
//
// What this does not check: the OpenAPI posture response, which is still
// described in prose (contracttest: getCompliancePosture is
// reasonSchemaNotYetWritten), nor other posture messages.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/proto/pb"
)

// knownUndeclaredEmergencyAccessFields are REST fields the proto message does
// not declare yet. Each entry must stay undeclared: once a field is added to the
// proto the test below fails until its entry is removed.
var knownUndeclaredEmergencyAccessFields = map[string]string{
	"unreviewed_activations":        "ADR-112 review surfacing never reached the proto; separate change",
	"oldest_unreviewed_age_hours":   "same as unreviewed_activations",
	"review_window_hours":           "same as unreviewed_activations",
	"independent_review_impossible": "same as unreviewed_activations",
}

func jsonFieldNames(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func TestEmergencyAccessPosture_RESTFieldsAreDeclaredInProto(t *testing.T) {
	msg := (&pb.EmergencyAccessPosture{}).ProtoReflect().Descriptor()
	declared := map[string]bool{}
	for i := 0; i < msg.Fields().Len(); i++ {
		declared[string(msg.Fields().Get(i).Name())] = true
	}

	rest := jsonFieldNames(t, reflect.TypeOf(core.EmergencyAccessPosture{}))
	require.NotEmpty(t, rest)
	for _, name := range rest {
		reason, exempt := knownUndeclaredEmergencyAccessFields[name]
		if exempt {
			assert.False(t, declared[name], "%s is declared in the proto now: remove it from knownUndeclaredEmergencyAccessFields (%s)", name, reason)
			continue
		}
		assert.True(t, declared[name], "core.EmergencyAccessPosture returns %q over REST but pb.EmergencyAccessPosture does not declare it", name)
	}
	for name := range knownUndeclaredEmergencyAccessFields {
		assert.Contains(t, rest, name, "stale exemption: core no longer returns %q", name)
	}
}
