// read_quota_alerts.go — proactive read-quota notifications.
//
// CheckReadQuotas scans all secrets with MaxReads > 0 and emits in-app
// Notification rows for those approaching their read limit. Thresholds:
//
//   - 80–94% of MaxReads → Warning
//   - 95–99% of MaxReads → Critical
//   - 100% (MaxReads reached) → Critical with "exhausted" label
//
// Notifications are deduplicated: a secret that already has an unread quota
// notification at the same or higher severity is skipped (or escalated in
// place when the new severity is strictly higher — matching the dedup pattern
// in role_expiry_notify.go).
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Notification type constants for read-quota alerts.
const (
	NotificationReadQuotaWarning  = "read_quota_warning"
	NotificationReadQuotaCritical = "read_quota_critical"
)

// readQuotaWarnThreshold is the percentage at which a Warning is emitted.
const readQuotaWarnThreshold = 80

// readQuotaCriticalThreshold is the percentage at which a Critical is emitted.
const readQuotaCriticalThreshold = 95

// ReadQuotaCheckResult summarises what was emitted by CheckReadQuotas.
type ReadQuotaCheckResult struct {
	Warnings  int // secrets at 80–94% of MaxReads
	Criticals int // secrets at 95%+ of MaxReads
	Exhausted int // secrets at exactly 100% (MaxReads reached)
	Checked   int // total secrets with MaxReads > 0
}

// CheckReadQuotas scans all secrets with MaxReads > 0 and emits in-app
// Notification rows for those approaching or reaching their read limit.
// Deduplicates: skips secrets that already have an unread quota notification
// at the same or higher severity.
func (k *KeyorixCore) CheckReadQuotas(ctx context.Context) (*ReadQuotaCheckResult, error) {
	secrets, err := k.storage.ListSecretsWithQuota(ctx)
	if err != nil {
		return nil, fmt.Errorf("list secrets with quota: %w", err)
	}

	result := &ReadQuotaCheckResult{}
	for i := range secrets {
		s := &secrets[i]
		if s.MaxReads == nil || *s.MaxReads <= 0 {
			continue
		}
		result.Checked++

		pct := QuotaUsagePct(s.ReadCount, *s.MaxReads)
		if pct < readQuotaWarnThreshold {
			continue
		}

		exhausted := pct >= 100
		severity := quotaSeverity(pct)
		title, msg := quotaMessage(s.Name, s.ReadCount, *s.MaxReads, exhausted)
		nType := quotaNotificationType(severity)

		// #G21: this check-then-act (read here, CreateNotification below) has no
		// DB-level backstop — unlike rotation/expiry reminders, which get one from
		// uniq_notifications_unread_reminder (#488). That index can't simply be
		// extended to cover read-quota notifications: it's keyed on (user_id,
		// type, project_id), but read-quota dedup is per-SECRET (unreadQuotaNotification
		// matches on secretID via Link content, see below) — a blanket per-project
		// index would silently drop a legitimate second secret's notification
		// while the first is still unread. A correct fix needs a stable,
		// structured dedup key (not the current strings.Contains(Link, ...)
		// content match — see G22, the same underlying gap) plus a schema
		// migration; deferred as a larger, separate change. Worst case today is
		// a duplicate notification under a genuine concurrent-run race, not a
		// security or data-integrity issue.
		existing := k.unreadQuotaNotification(ctx, s.OwnerID, s.ID)
		if existing != nil {
			if severity <= existing.Severity {
				continue // same or lower severity — don't pile up
			}
			if k.upgradeReminder(ctx, existing, title, msg, severity) {
				k.bumpQuotaCount(result, severity, exhausted)
			}
			continue
		}

		link := fmt.Sprintf("/secrets/%d", s.ID)
		k.notifyWithSeverity(ctx, s.OwnerID, nType, title, msg, nil, link, severity)
		k.bumpQuotaCount(result, severity, exhausted)
	}
	return result, nil
}

// ListSecretsWithQuota returns all live secrets with MaxReads > 0 for the
// quota-report endpoint. Thin pass-through to storage; no authz filtering —
// the caller (HTTP handler) must gate on secrets.read before invoking.
func (k *KeyorixCore) ListSecretsWithQuota(ctx context.Context) ([]models.SecretNode, error) {
	return k.storage.ListSecretsWithQuota(ctx)
}

// QuotaUsagePct returns the usage percentage (0–100) for a secret.
// Returns 0 if maxReads is 0 or negative.
func QuotaUsagePct(readCount, maxReads int) int {
	if maxReads <= 0 {
		return 0
	}
	pct := (readCount * 100) / maxReads
	if pct > 100 {
		return 100
	}
	return pct
}

// quotaSeverity maps a usage percentage to a NotificationSeverity.
func quotaSeverity(pct int) models.NotificationSeverity {
	if pct >= readQuotaCriticalThreshold {
		return models.NotificationSeverityCritical
	}
	return models.NotificationSeverityWarning
}

// quotaNotificationType returns the notification type string for the severity.
func quotaNotificationType(severity models.NotificationSeverity) string {
	if severity >= models.NotificationSeverityCritical {
		return NotificationReadQuotaCritical
	}
	return NotificationReadQuotaWarning
}

// quotaMessage builds the notification title and body for a read-quota alert.
func quotaMessage(name string, readCount, maxReads int, exhausted bool) (string, string) {
	if exhausted {
		return "Secret read quota exhausted",
			fmt.Sprintf("Secret %q has reached its read limit (%d/%d reads used). No further reads are permitted.", name, readCount, maxReads)
	}
	pct := QuotaUsagePct(readCount, maxReads)
	return "Secret read quota alert",
		fmt.Sprintf("Secret %q has used %d%% of its read quota (%d/%d reads).", name, pct, readCount, maxReads)
}

// bumpQuotaCount increments the appropriate counters on result.
func (k *KeyorixCore) bumpQuotaCount(result *ReadQuotaCheckResult, severity models.NotificationSeverity, exhausted bool) {
	if severity >= models.NotificationSeverityCritical {
		result.Criticals++
		if exhausted {
			result.Exhausted++
		}
	} else {
		result.Warnings++
	}
}

// unreadQuotaNotification returns the secret owner's existing unread quota
// notification for a specific secret, or nil if none exists.
func (k *KeyorixCore) unreadQuotaNotification(ctx context.Context, userID, secretID uint) *models.Notification {
	notes, err := k.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil // on read error, prefer notifying over silently skipping
	}
	needle := fmt.Sprintf("/secrets/%d", secretID)
	for _, n := range notes {
		if (n.Type == NotificationReadQuotaWarning || n.Type == NotificationReadQuotaCritical) &&
			strings.Contains(n.Link, needle) {
			return n
		}
	}
	return nil
}
