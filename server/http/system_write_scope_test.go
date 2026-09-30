// system_write_scope_test.go — ADR-110's guard: every route gated by
// permSystemWrite in server/http/router.go must appear in
// systemWriteScopeAllowlist below with a written reason (what it mutates,
// why system.write and not a narrower permission). Reuses
// permission_sweep_test.go's own scanRouter/trackedGatePerms AST walk rather
// than duplicating it — that scan already resolves every route's full
// mounted path and collects both permSystemRead and permSystemWrite sites in
// one pass (see that file's own package doc for the trackedGatePerms
// rationale).
//
// Verified RED against a reverted allowlist (emptied it to {}): every one of
// the current permSystemWrite call sites reported as unallowed. GREEN with
// the real allowlist below restored. F1 (ADR-110 follow-up, Andrei
// 2026-09-28) split notification channels, escalation policies, and 5 of the
// 11 /admin/jobs triggers off onto alerts.write; anomaly-alerts,
// compliance-digest, and run-alert-escalation are notification-only but
// deliberately stayed here (see their entries below) — see
// alerts_write_scope_test.go for the alerts.write allowlist, and
// docs/adr-110-system-write-scope.md's Decision section for the current,
// post-split route table.
package http

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// systemWriteScopeAllowlist maps ROUTE IDENTITY ("<METHOD> <full mounted
// path>", or "USE <group path>" for a group-level r.Use(...) gate — same
// convention as permissionSweepAllowlist) to a written justification: what
// the route mutates, and why system.write is the right tier rather than an
// existing narrower permission. Every entry here was reviewed in
// docs/adr-110-system-write-scope.md's own table — this allowlist is that
// review's enforcement mechanism, not a duplicate of it; see that ADR for
// the full reasoning per row.
var systemWriteScopeAllowlist = map[string]string{
	"POST /api/v1/audit/checkpoint":                   "Writes a new audit-hash-chain checkpoint — mutates the tamper-evidence dataset itself, one tier above the group's own audit.read baseline.",
	"POST /api/v1/audit/migrate-chain-encoding":       "One-time migration of the audit hash chain's on-disk encoding — same bar as /checkpoint immediately above.",
	"POST /api/v1/audit/anomalies/{id}/acknowledge":   "Dismisses a security-detection record. Sits inside the /audit group's own audit.read r.Use(), so this route effectively requires BOTH audit.read and system.write (chi's With() adds to, not replaces, the group's Use()) — the same reasoning permissionSweepAllowlist's sibling 'GET /api/v1/audit/anomalies' entry documents.",
	"GET /api/v1/admin/scheduler-metrics":             "A GET gated on a WRITE permission, deliberately: exact scheduler-tick timestamps let an unauthenticated caller predict a security-relevant job's next execution (a timing side channel, per the route's own adjacent comment) — moving this to system.read (the universal auto-granted baseline) would WIDEN who can read it, not narrow it. See ADR-110's row #15 for the full reasoning.",
	"POST /api/v1/compliance/snapshots":               "Triggers a full compliance-posture evaluation and persists a snapshot row. The GET sibling (ListComplianceSnapshots) is correctly audit.read; POST is deliberately one tier up.",
	"POST /api/v1/legal-hold":                         "Places a legal hold (ISO A.5.34) — an admin action, not a read disclosure (the GET sibling is audit.read).",
	"DELETE /api/v1/legal-hold":                       "Lifts a legal hold — same reasoning as POST immediately above.",
	"POST /api/v1/risk-exceptions":                    "Creates a risk-register entry (ISO A.5.8) — the GET sibling (list) is audit.read; create/approve/revoke is deliberately system.write.",
	"POST /api/v1/risk-exceptions/{id}/approve":       "Approves a risk-register entry — same family as create immediately above.",
	"DELETE /api/v1/risk-exceptions/{id}":             "Revokes a risk-register entry — same family as create above.",
	"POST /api/v1/sod/policies":                       "Creates a separation-of-duties policy (which permission pairs conflict) — the GET sibling (policy definitions, no PII) is baseline system.read; create/delete the rule other RBAC grants get checked against is deliberately one tier up.",
	"DELETE /api/v1/sod/policies/{id}":                "Deletes an SoD policy — same family as create immediately above.",
	"POST /api/v1/admin/jobs/anomaly-alerts":          "F1 (ADR-110 follow-up) split the /admin/jobs group's single gate per-route. RunAnomalyAlerts is notification-only, but deliberately excluded from the alerts.write split: an alert_operator (no audit/compliance authority by design) could point a notification channel they control at this trigger and exfiltrate anomaly-detection findings — an SSRF path from air-gapped hosts too. Stays on system.write.",
	"POST /api/v1/admin/jobs/compliance-digest":       "Same F1 split, same reasoning as anomaly-alerts immediately above — RunComplianceDigest is notification-only but would let an alert_operator exfiltrate compliance posture via a channel they control. Stays on system.write.",
	"POST /api/v1/admin/jobs/run-alert-escalation":    "Same F1 split, same reasoning as anomaly-alerts above — RunEscalation dispatches unacknowledged ANOMALY alerts (the same data class anomaly-alerts sends), so it stays on system.write for the identical exfiltration-path reason rather than moving to alerts.write.",
	"POST /api/v1/admin/jobs/record-hygiene-snapshot": "Same F1 split. This one persists a HygieneTrendSnapshot row (data persistence, not a notification) — verified by reading hygiene_trends.go's RecordHygieneSnapshot — so it stays on system.write; the pure notification/reminder triggers in this same group moved to alerts.write (see alertsWriteScopeAllowlist in alerts_write_scope_test.go).",
	"POST /api/v1/admin/jobs/suspend-inactive-users":  "Same F1 split — SuspendInactiveUsers mutates account state (inactivity_suspend.go), a real account-state mutation, not a notification.",
	"POST /api/v1/admin/jobs/purge-audit-logs":        "Same F1 split — PurgeAuditLogsJob deletes audit events (audit_retention_handler.go), a data mutation, not a notification.",
	"PUT /api/v1/admin/anomaly-config":                "Persists DB-backed anomaly-detection thresholds — the GET sibling is correctly system.read (config values, no per-tenant data); the PUT is a deployment-wide detection-tuning mutation with no narrower fit.",
}

// TestSystemWriteRouteAllowlistCoversEveryGateSite is ADR-110's guard: every
// RequirePermission(permSystemWrite)/RequireScopedPermission(permSystemWrite, ...)
// call site in server/http/router.go must appear in systemWriteScopeAllowlist.
// A new route gated on system.write with no allowlist entry fails this test —
// forcing the same "what does it mutate, why system.write and not narrower"
// review this ADR gave the current 25 sites.
func TestSystemWriteRouteAllowlistCoversEveryGateSite(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	_, foundAll := scanRouter(t, routerGoPath)

	found := map[string]systemReadSite{}
	for key, s := range foundAll {
		if s.perm == "permSystemWrite" {
			found[key] = s
		}
	}
	if len(found) == 0 {
		t.Fatal("found 0 RequirePermission(permSystemWrite)/RequireScopedPermission(permSystemWrite, " +
			"...) call sites in router.go — this guard is now vacuous and is no longer checking " +
			"anything; fix the scan (trackedGatePerms in permission_sweep_test.go), not this assertion")
	}

	var unallowed []string
	for key, s := range found {
		if _, ok := systemWriteScopeAllowlist[key]; !ok {
			unallowed = append(unallowed, fmt.Sprintf("%s (router.go:%d, %s(permSystemWrite))", key, s.line, s.fn))
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"server/http/router.go gates a route on permSystemWrite with no reviewed ADR-110 "+
			"allowlist entry — add one to systemWriteScopeAllowlist (this file) naming what the "+
			"route mutates and why system.write, not a narrower permission, is correct: %v", unallowed)
}

// TestSystemWriteScopeAllowlistEntriesStillExist is the flip side: an
// allowlist entry for a route that no longer exists (renamed, deleted, or
// regressed onto a different route) would silently stop covering anything —
// mirrors permission_sweep_test.go's TestPermissionSweepAllowlistEntriesStillExist.
func TestSystemWriteScopeAllowlistEntriesStillExist(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	_, found := scanRouter(t, routerGoPath)

	var stale []string
	for key := range systemWriteScopeAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"systemWriteScopeAllowlist entry no longer matches any real permSystemWrite call site in "+
			"server/http/router.go (the route moved, was re-gated, or was deleted, without updating "+
			"this list): %v", stale)
}

// TestSystemWriteScopeAllowlistJustificationsAreNonEmpty mirrors
// permission_sweep_test.go's identical guard for its own allowlist.
func TestSystemWriteScopeAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range systemWriteScopeAllowlist {
		assert.NotEmpty(t, reason, "systemWriteScopeAllowlist entry %q has no justification", key)
	}
}
