// alerts_write_scope_test.go — F1's guard (ADR-110 follow-up, Andrei
// 2026-09-28): every route gated by permAlertsWrite in server/http/router.go
// must appear in alertsWriteScopeAllowlist below with a written reason.
// Reuses permission_sweep_test.go's own scanRouter/trackedGatePerms AST walk
// rather than duplicating it -- same convention as system_write_scope_test.go's
// ADR-110 sweep, which this file is the sibling of: alerts.write is the
// permission F1 split off system.write for the narrower "alerting operator"
// persona (notification channels, escalation policies, and the on-demand job
// triggers that only ever emit/dispatch a notification, never mutate account/
// role/audit state).
//
// Verified RED against a reverted allowlist (emptied it to {}): all 19 current
// permAlertsWrite call sites reported as unallowed. GREEN with the real
// allowlist below restored.
package http

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// alertsWriteScopeAllowlist maps ROUTE IDENTITY ("<METHOD> <full mounted
// path>" -- same convention as systemWriteScopeAllowlist/
// permissionSweepAllowlist; every permAlertsWrite site here is gated via a
// direct .With(...) on one route, never a group-level r.Use(...), so no "USE"
// keys exist in this allowlist) to a written justification: what the route
// does, and why it was verified to be a pure notification/config action
// rather than a data/account mutation that should have stayed on
// system.write. See docs/adr-110-system-write-scope.md's Decision section for
// the full per-route review.
var alertsWriteScopeAllowlist = map[string]string{
	"GET /api/v1/notification-channels":                   "Notification-channel config (webhook/Slack/Teams/email URLs where alerts go) -- the alerting-operator persona's core resource.",
	"POST /api/v1/notification-channels":                  "Same family as GET immediately above -- creates a channel.",
	"GET /api/v1/notification-channels/{id}":              "Same family -- reads one channel's config.",
	"PUT /api/v1/notification-channels/{id}":              "Same family -- updates one channel's config.",
	"DELETE /api/v1/notification-channels/{id}":           "Same family -- deletes a channel.",
	"PUT /api/v1/notification-channels/{id}/retry-policy": "Same family -- tunes one channel's retry policy.",
	"POST /api/v1/alert-escalation-policies":              "Escalation-policy definitions (severity threshold, minutes-until-escalate, target channels) -- same alerting-operator persona as notification channels.",
	"GET /api/v1/alert-escalation-policies":               "Same family -- lists policies.",
	"GET /api/v1/alert-escalation-policies/{id}":          "Same family -- reads one policy.",
	"PUT /api/v1/alert-escalation-policies/{id}":          "Same family -- updates one policy.",
	"DELETE /api/v1/alert-escalation-policies/{id}":       "Same family -- deletes one policy.",
	"POST /api/v1/admin/jobs/anomaly-alerts":              "RunAnomalyAlerts -> core.AlertNewAnomalies: broadcasts alerts for new anomaly findings. Verified by reading the core function -- emits notifications only, no state mutation.",
	"POST /api/v1/admin/jobs/rotation-reminders":          "RunRotationReminders -> core.SendRotationReminders: sends rotation-due reminders. Notification-only.",
	"POST /api/v1/admin/jobs/expiry-reminders":            "RunExpiryReminders -> core.SendExpiryReminders: sends secret-expiry reminders. Notification-only.",
	"POST /api/v1/admin/jobs/compliance-digest":           "RunComplianceDigest -> core.SendComplianceDigest: broadcasts the compliance digest. Notification-only.",
	"POST /api/v1/admin/jobs/role-expiry-check":           "RunRoleExpiryCheck -> core.CheckRoleExpiry (role_expiry_notify.go): emits in-app Notification rows for role grants nearing expiry. Verified by reading the function -- it does NOT revoke anything; its own doc comment says already-expired grants are left to a separate removal sweep. Notification-only, so it moved here despite not being on this item's original expected list.",
	"POST /api/v1/admin/jobs/check-read-quotas":           "RunReadQuotaCheck -> core.CheckReadQuotas (read_quota_alerts.go): emits in-app Notification rows for secrets approaching their MaxReads limit. Verified by reading the function -- it does NOT block or enforce reads (that happens elsewhere, at actual read time); this job only notifies. Notification-only, so it moved here despite not being on this item's original expected list.",
	"POST /api/v1/admin/jobs/run-alert-escalation":        "RunEscalation -> core.RunAlertEscalation (alert_escalation.go): dispatches unacknowledged anomaly alerts to configured notification channels per escalation policy. Verified by reading the function -- no alert-row mutation (no \"escalated\" flag set), pure dispatch.",
	"POST /api/v1/admin/jobs/token-expiry-check":          "RunTokenExpiryCheck -> core.CheckTokenExpiry (token_expiry_remind.go): emits in-app Notification rows for PATs/machine credentials nearing expiry. Notification-only, mirrors role-expiry-check's pattern exactly per its own doc comment.",
}

// TestAlertsWriteRouteAllowlistCoversEveryGateSite is F1's guard: every
// RequirePermission(permAlertsWrite)/RequireScopedPermission(permAlertsWrite,
// ...) call site in server/http/router.go must appear in
// alertsWriteScopeAllowlist. A new route gated on alerts.write with no
// allowlist entry fails this test -- forcing the same "what does it do, why
// alerts.write" review this item gave the current 19 sites.
func TestAlertsWriteRouteAllowlistCoversEveryGateSite(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	_, foundAll := scanRouter(t, routerGoPath)

	found := map[string]systemReadSite{}
	for key, s := range foundAll {
		if s.perm == "permAlertsWrite" {
			found[key] = s
		}
	}
	if len(found) == 0 {
		t.Fatal("found 0 RequirePermission(permAlertsWrite)/RequireScopedPermission(permAlertsWrite, " +
			"...) call sites in router.go — this guard is now vacuous and is no longer checking " +
			"anything; fix the scan (trackedGatePerms in permission_sweep_test.go), not this assertion")
	}

	var unallowed []string
	for key, s := range found {
		if _, ok := alertsWriteScopeAllowlist[key]; !ok {
			unallowed = append(unallowed, fmt.Sprintf("%s (router.go:%d, %s(permAlertsWrite))", key, s.line, s.fn))
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"server/http/router.go gates a route on permAlertsWrite with no reviewed F1 "+
			"allowlist entry — add one to alertsWriteScopeAllowlist (this file) naming what the "+
			"route does and why alerts.write is correct: %v", unallowed)
}

// TestAlertsWriteScopeAllowlistEntriesStillExist is the flip side: an
// allowlist entry for a route that no longer exists (renamed, deleted, or
// regressed onto a different permission) would silently stop covering
// anything -- mirrors system_write_scope_test.go's identical guard.
func TestAlertsWriteScopeAllowlistEntriesStillExist(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	_, found := scanRouter(t, routerGoPath)

	var stale []string
	for key := range alertsWriteScopeAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"alertsWriteScopeAllowlist entry no longer matches any real permAlertsWrite call site in "+
			"server/http/router.go (the route moved, was re-gated, or was deleted, without updating "+
			"this list): %v", stale)
}

// TestAlertsWriteScopeAllowlistJustificationsAreNonEmpty mirrors
// system_write_scope_test.go's identical guard for its own allowlist.
func TestAlertsWriteScopeAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range alertsWriteScopeAllowlist {
		assert.NotEmpty(t, reason, "alertsWriteScopeAllowlist entry %q has no justification", key)
	}
}
