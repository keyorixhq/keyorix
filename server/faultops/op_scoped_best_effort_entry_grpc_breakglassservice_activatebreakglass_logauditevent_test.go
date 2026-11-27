// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// The gRPC twin of post_projects_id_break_glass_logauditevent: the same core
	// ActivateBreakGlass, the same BREAKGLASS-OWED-1 degraded commit with owed audit
	// rows, gated on the same degraded-path log line.
	registerOpScopedBestEffort("grpc_breakglassservice_activatebreakglass_logauditevent", opScopedBestEffortTable{
		op: "GRPC keyorix.v1.BreakGlassService.ActivateBreakGlass", method: "LogAuditEvent",
		tables:              []string{"AuditEvent", "BreakGlassActivation", "Notification", "PendingAuditEvent"},
		requireLogSubstring: "is DEGRADED: user",
		pinnedKinds:         []faultstorage.FaultKind{faultstorage.KindError},
	})
}
