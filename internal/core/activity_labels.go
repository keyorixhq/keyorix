package core

import "strings"

// activityLabels maps a raw audit event type to the phrase the dashboard shows
// after the actor ("<actor> <label> <secret>"). The raw type stays available to
// clients as ActivityItem.EventType; this is display only (#2951).
//
// Types missing here still get a readable label from humanizeEventType, so the
// dashboard never shows "secret.dependency_invalidated"; add an entry when the
// generated wording is not good enough.
var activityLabels = map[string]string{ // #nosec G101 -- audit event types mapped to display phrases, not credentials
	"secret.read":                   "accessed secret",
	"secret.versions_listed":        "listed versions of secret",
	"secret.created":                "created secret",
	"secret.updated":                "updated secret",
	"secret.deleted":                "deleted secret",
	"secret.restored":               "restored secret",
	"secret.rotated":                "rotated secret",
	"secret.shared":                 "shared secret",
	"share.revoked":                 "revoked a share of secret",
	"secret.dependency_added":       "added a dependency to secret",
	"secret.dependency_removed":     "removed a dependency from secret",
	"secret.dependency_invalidated": "broke a dependency of secret",
	"secret.dependency_restored":    "restored a dependency of secret",
	"role.assigned":                 "assigned a role",
	"role.removed":                  "removed a role",
	"role.expired":                  "had a role expire",
	"break_glass.activated":         "activated break-glass access",
	"break_glass.revoked":           "revoked break-glass access",
	"break_glass.reviewed":          "reviewed a break-glass activation",
	"break_glass.review_overdue":    "has a break-glass review overdue",
	"auth.login":                    "logged in",
	"auth.logout":                   "logged out",
	"auth.password_reset":           "reset a password",
	"access_review.revoked":         "revoked access in an access review",
	"access_review.attested":        "attested an access review",
	"access_review.campaign_opened": "opened an access review campaign",
	"access_review.campaign_closed": "closed an access review campaign",
	"secret.auto_rotated":           "auto-rotated secret",
	"secret.rotate_failed":          "failed to rotate secret",
	"secret.acl_granted":            "granted access to secret",
	"secret.acl_revoked":            "revoked access to secret",
	"anomaly.detected":              "was flagged by anomaly detection",
	"account.locked":                "locked an account",
	"account.unlocked":              "unlocked an account",
	"project.created":               "created project",
	"project.updated":               "updated project",
	"project.deleted":               "deleted project",
	"impersonation.start":           "started impersonating a user",
	"impersonation.end":             "stopped impersonating a user",
	"permission.assigned":           "added a permission",
	"permission.removed":            "removed a permission",
	"group.member_added":            "added a group member",
	"group.member_removed":          "removed a group member",
}

// ActivityLabel returns the human-readable phrase for an audit event type. It
// never returns the raw dotted/underscored type.
func ActivityLabel(eventType string) string {
	if l, ok := activityLabels[eventType]; ok {
		return l
	}
	return humanizeEventType(eventType)
}

// humanizeEventType turns "resource.some_action" into "resource some action".
func humanizeEventType(eventType string) string {
	s := strings.NewReplacer(".", " ", "_", " ").Replace(eventType)
	return strings.TrimSpace(s)
}
