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
// the 25 current permSystemWrite call sites reported as unallowed. GREEN
// with the real allowlist below restored.
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
	"GET /api/v1/notification-channels":                   "Notification-channel config (webhook/Slack/Teams/email URLs where alerts go). No narrower permission exists in the catalog for this resource family — see ADR-110.",
	"POST /api/v1/notification-channels":                  "Same family as GET immediately above — creates a channel.",
	"GET /api/v1/notification-channels/{id}":              "Same family — reads one channel's config.",
	"PUT /api/v1/notification-channels/{id}":              "Same family — updates one channel's config.",
	"DELETE /api/v1/notification-channels/{id}":           "Same family — deletes a channel.",
	"PUT /api/v1/notification-channels/{id}/retry-policy": "Same family — tunes one channel's retry policy.",
	"POST /api/v1/alert-escalation-policies":              "Escalation-policy definitions (severity threshold, minutes-until-escalate, target channels). Same reasoning as notification channels — no narrower permission exists.",
	"GET /api/v1/alert-escalation-policies":               "Same family — lists policies.",
	"GET /api/v1/alert-escalation-policies/{id}":          "Same family — reads one policy.",
	"PUT /api/v1/alert-escalation-policies/{id}":          "Same family — updates one policy.",
	"DELETE /api/v1/alert-escalation-policies/{id}":       "Same family — deletes one policy.",
	"POST /api/v1/audit/checkpoint":                       "Writes a new audit-hash-chain checkpoint — mutates the tamper-evidence dataset itself, one tier above the group's own audit.read baseline.",
	"POST /api/v1/audit/migrate-chain-encoding":           "One-time migration of the audit hash chain's on-disk encoding — same bar as /checkpoint immediately above.",
	"POST /api/v1/audit/anomalies/{id}/acknowledge":       "Dismisses a security-detection record. Sits inside the /audit group's own audit.read r.Use(), so this route effectively requires BOTH audit.read and system.write (chi's With() adds to, not replaces, the group's Use()) — the same reasoning permissionSweepAllowlist's sibling 'GET /api/v1/audit/anomalies' entry documents.",
	"GET /api/v1/admin/scheduler-metrics":                 "A GET gated on a WRITE permission, deliberately: exact scheduler-tick timestamps let an unauthenticated caller predict a security-relevant job's next execution (a timing side channel, per the route's own adjacent comment) — moving this to system.read (the universal auto-granted baseline) would WIDEN who can read it, not narrow it. See ADR-110's row #15 for the full reasoning.",
	"POST /api/v1/compliance/snapshots":                   "Triggers a full compliance-posture evaluation and persists a snapshot row. The GET sibling (ListComplianceSnapshots) is correctly audit.read; POST is deliberately one tier up.",
	"POST /api/v1/legal-hold":                             "Places a legal hold (ISO A.5.34) — an admin action, not a read disclosure (the GET sibling is audit.read).",
	"DELETE /api/v1/legal-hold":                           "Lifts a legal hold — same reasoning as POST immediately above.",
	"POST /api/v1/risk-exceptions":                        "Creates a risk-register entry (ISO A.5.8) — the GET sibling (list) is audit.read; create/approve/revoke is deliberately system.write.",
	"POST /api/v1/risk-exceptions/{id}/approve":           "Approves a risk-register entry — same family as create immediately above.",
	"DELETE /api/v1/risk-exceptions/{id}":                 "Revokes a risk-register entry — same family as create above.",
	"POST /api/v1/sod/policies":                           "Creates a separation-of-duties policy (which permission pairs conflict) — the GET sibling (policy definitions, no PII) is baseline system.read; create/delete the rule other RBAC grants get checked against is deliberately one tier up.",
	"DELETE /api/v1/sod/policies/{id}":                    "Deletes an SoD policy — same family as create immediately above.",
	"USE /api/v1/admin/jobs":                              "On-demand triggers for background jobs that otherwise only run on their own schedulers (anomaly-alerts, rotation-reminders, expiry-reminders, compliance-digest, record-hygiene-snapshot, role-expiry-check, check-read-quotas, token-expiry-check, suspend-inactive-users, purge-audit-logs) — a deployment-wide administrative action with no narrower existing permission family; every handler wraps a core function with no additional in-handler authorization, so the route gate is the only check.",
	"PUT /api/v1/admin/anomaly-config":                    "Persists DB-backed anomaly-detection thresholds — the GET sibling is correctly system.read (config values, no per-tenant data); the PUT is a deployment-wide detection-tuning mutation with no narrower fit.",
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
