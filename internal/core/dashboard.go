package core

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ExpiringSecret represents a secret that is expiring soon or has already expired.
type ExpiringSecret struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Environment string    `json:"environment"`
	ExpiresAt   time.Time `json:"expiresAt"`
	DaysLeft    int       `json:"daysLeft"` // negative = already expired N days ago
	Expired     bool      `json:"expired"`  // true when expiration is in the past
}

// StatTrend contains trend data for a dashboard stat.
type StatTrend struct {
	Value      float64 `json:"value"`      // % change vs previous snapshot
	IsPositive bool    `json:"isPositive"` // true = grew, false = shrank
}

// DashboardStats contains summary statistics for the dashboard.
//
// #394: every deployment-wide sub-check gated behind hasAuditRead below (and the
// expiring-secrets rollup) is queried best-effort so one failing signal doesn't
// abort the whole dashboard — but a query failure must never read the same as
// "checked, genuinely zero" (e.g. FailedAuthAttempts24h=0 on an audit-log query
// error looks identical to a clean 24h window and could mask an ongoing
// incident or audit-log outage). Degraded + DegradedReasons make a partial
// snapshot detectable instead of indistinguishable from a fully-clean one,
// mirroring the CompliancePosture.Degraded convention (compliance_posture.go).
type DashboardStats struct {
	TotalSecrets          int64            `json:"totalSecrets"`
	SharedSecrets         int              `json:"sharedSecrets"`
	SecretsSharedWithMe   int              `json:"secretsSharedWithMe"`
	ActiveUsers           int64            `json:"activeUsers"`
	AuditEvents30d        int64            `json:"auditEvents30d"`
	AuditLogins30d        int64            `json:"auditLogins30d"`
	AuditSecretReads30d   int64            `json:"auditSecretReads30d"`
	FailedAuthAttempts24h int64            `json:"failedAuthAttempts24h"`
	InactiveUsers         int64            `json:"inactiveUsers"`
	PrevTotalSecrets       *int64     `json:"prevTotalSecrets,omitempty"`
	TotalSecretsTrend      *StatTrend `json:"totalSecretsTrend,omitempty"`
	SharedSecretsTrend     *StatTrend `json:"sharedSecretsTrend,omitempty"`
	SharedWithMeTrend      *StatTrend `json:"sharedWithMeTrend,omitempty"`
	PrevActiveUsers        *int64     `json:"prevActiveUsers,omitempty"`
	ActiveUsersTrend       *StatTrend `json:"activeUsersTrend,omitempty"`
	PrevAuditEvents30d     *int64     `json:"prevAuditEvents30d,omitempty"`
	AuditEvents30dTrend    *StatTrend `json:"auditEvents30dTrend,omitempty"`
	ExpiringSecrets       []ExpiringSecret `json:"expiringSecrets,omitempty"`
	RecentActivity        []ActivityItem   `json:"recentActivity"`
	// Degraded is true when one or more sub-checks above could not be queried —
	// the zero/empty values they carry are UNKNOWN, not verified-clean. A
	// consumer must treat a degraded snapshot as incomplete, not as a clean
	// read (e.g. FailedAuthAttempts24h=0 does NOT mean "no failed auth" when
	// Degraded is true).
	Degraded bool `json:"degraded"`
	// DegradedReasons names each failed sub-check with its underlying error.
	DegradedReasons []string `json:"degradedReasons,omitempty"`
}

// degrade records that a dashboard sub-check could not be queried: it flips
// Degraded and appends a human-readable reason, so a consumer can tell "queried,
// genuinely zero" apart from "query failed, treat as unknown" — mirroring
// CompliancePosture.degrade (compliance_posture.go).
func (s *DashboardStats) degrade(area string, err error) {
	s.Degraded = true
	s.DegradedReasons = append(s.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// ActivityItem represents a single entry in the activity feed.
type ActivityItem struct {
	ID         uint      `json:"id"`
	Type       string    `json:"type"`
	SecretName string    `json:"secretName"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
}

// ActivityFeed is the paginated response for the activity endpoint.
type ActivityFeed struct {
	Items    []ActivityItem `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

// GetDashboardStats returns summary counts and recent activity for the authenticated user.
func (c *KeyorixCore) GetDashboardStats(ctx context.Context, userID uint, username string) (*DashboardStats, error) {
	stats := &DashboardStats{}

	_, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &username,
		Page:      1,
		PageSize:  1,
	})
	if err != nil {
		total = 0
		stats.degrade("total_secrets", err)
	}

	outgoing, err := c.storage.ListSharesByOwner(ctx, userID)
	sharedSecrets := 0
	if err == nil {
		sharedSecrets = len(outgoing)
	} else {
		stats.degrade("shared_secrets", err)
	}

	incoming, err := c.storage.ListSharesByUser(ctx, userID)
	sharedWithMe := 0
	if err == nil {
		sharedWithMe = len(incoming)
	} else {
		stats.degrade("shared_with_me", err)
	}

	// GetDashboardStats is reachable by any caller holding at least the universal
	// system_viewer baseline (system.read is enforced in the router) — every regular
	// user's own home dashboard. Only a genuinely elevated caller (audit.read:
	// system_admin/system_auditor) may see the DEPLOYMENT-WIDE aggregates mixed into
	// this same payload (active-user count, audit-event counts, failed-auth count,
	// inactive-user count): a zero-project-membership baseline account has no
	// legitimate route to org-wide numbers otherwise (#272). Recent activity gets the
	// same treatment, scoped to the caller's own events when they lack audit.read, so
	// the dashboard never leaks secret names/actions from projects the caller can't
	// read.
	hasAuditRead, _ := c.Authorize(ctx, userID, "audit.read", Scope{})

	var auditActor *uint
	if !hasAuditRead {
		auditActor = &userID
	}
	events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		UserID:   auditActor,
		Page:     1,
		PageSize: 5,
	})
	if err != nil {
		stats.degrade("recent_activity", err)
	}
	recent := make([]ActivityItem, 0, len(events))
	for _, e := range events {
		recent = append(recent, mapAuditEventToActivity(e, username))
	}

	expiringSecrets, err := c.getExpiringSecrets(ctx, username)
	if err != nil {
		stats.degrade("expiring_secrets", err)
	}

	var activeUsers, auditCount, auditLogins, auditSecretReads, failedAuth24h, inactiveUsers int64
	if hasAuditRead {
		activeUsers, auditCount, auditLogins, auditSecretReads, failedAuth24h, inactiveUsers = c.fetchAdminDashboardStats(ctx, stats)
	}

	stats.TotalSecrets = total
	stats.SharedSecrets = sharedSecrets
	stats.SecretsSharedWithMe = sharedWithMe
	stats.ActiveUsers = activeUsers
	stats.AuditEvents30d = auditCount
	stats.AuditLogins30d = auditLogins
	stats.AuditSecretReads30d = auditSecretReads
	stats.FailedAuthAttempts24h = failedAuth24h
	stats.InactiveUsers = inactiveUsers
	stats.RecentActivity = recent
	stats.ExpiringSecrets = expiringSecrets

	// Save today's deployment stats snapshot (once per UTC day) and compute trends.
	// Only meaningful when the caller holds audit.read and the admin stats were fetched.
	if hasAuditRead {
		todayDate := time.Now().UTC().Truncate(24 * time.Hour)
		prevSnap, snapErr := c.storage.GetPreviousDeploymentStatsSnapshot(ctx)
		if snapErr == nil { // tolerate failure — trends are best-effort
			newSnap := &models.DeploymentStatsSnapshot{
				ActiveUsers:    stats.ActiveUsers,
				AuditEvents30d: stats.AuditEvents30d,
				SnapshotDate:   todayDate,
			}
			_ = c.storage.SaveDeploymentStatsSnapshot(ctx, newSnap) // best-effort
			if prevSnap != nil {
				stats.PrevActiveUsers = &prevSnap.ActiveUsers
				stats.ActiveUsersTrend = computeTrend(float64(prevSnap.ActiveUsers), float64(stats.ActiveUsers))
				stats.PrevAuditEvents30d = &prevSnap.AuditEvents30d
				stats.AuditEvents30dTrend = computeTrend(float64(prevSnap.AuditEvents30d), float64(stats.AuditEvents30d))
			}
		}
	}

	prev, err := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if err == nil && prev != nil {
		stats.TotalSecretsTrend = computeTrend(float64(prev.TotalSecrets), float64(total))
		stats.SharedSecretsTrend = computeTrend(float64(prev.SharedSecrets), float64(sharedSecrets))
		stats.SharedWithMeTrend = computeTrend(float64(prev.SecretsSharedWithMe), float64(sharedWithMe))
		stats.PrevTotalSecrets = &prev.TotalSecrets
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	existing, _ := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if existing == nil || existing.SnapshotDate.Before(today) {
		_ = c.storage.SaveStatsSnapshot(ctx, &models.StatsSnapshot{
			UserID:              userID,
			TotalSecrets:        total,
			SharedSecrets:       sharedSecrets,
			SecretsSharedWithMe: sharedWithMe,
			SnapshotDate:        today,
		})
	}

	return stats, nil
}

// fetchAdminDashboardStats fetches the deployment-wide aggregates visible only to
// callers holding audit.read (active-user count, audit-event counts, failed-auth
// count, inactive-user count). Errors degrade the stats struct; all counts default
// to 0. Extracted from GetDashboardStats to reduce its cognitive complexity.
func (c *KeyorixCore) fetchAdminDashboardStats(ctx context.Context, stats *DashboardStats) (activeUsers, auditCount, auditLogins, auditSecretReads, failedAuth24h, inactiveUsers int64) {
	if storageStats, err := c.storage.GetStats(ctx); err == nil {
		activeUsers = storageStats.TotalUsers
	} else {
		stats.degrade("active_users", err)
	}
	thirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour)
	var auditErr error
	_, auditCount, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &thirtyDaysAgo, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("audit_count", auditErr)
	}
	authAction := "auth.login"
	_, auditLogins, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &thirtyDaysAgo, Action: &authAction, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("audit_logins", auditErr)
	}
	secretReadAction := "secret.read"
	_, auditSecretReads, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &thirtyDaysAgo, Action: &secretReadAction, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("audit_secret_reads", auditErr)
	}
	twentyFourHoursAgo := time.Now().UTC().Add(-24 * time.Hour)
	successFalse := false
	_, failedAuth24h, auditErr = c.storage.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &twentyFourHoursAgo, Success: &successFalse, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("failed_auth_24h", auditErr)
	}
	inactiveCutoff := thirtyDaysAgo
	_, inactiveUsers, auditErr = c.storage.ListUsers(ctx, &storage.UserFilter{InactiveSince: &inactiveCutoff, Page: 1, PageSize: 1})
	if auditErr != nil {
		stats.degrade("inactive_users", auditErr)
	}
	return
}

// GetActivityFeed returns a paginated, deployment-wide activity feed. userID is
// unused here (kept for signature symmetry with GetDashboardStats/call sites): the
// router's audit.read gate on GET /dashboard/activity is what authorizes seeing
// every user's events, so this function itself applies no per-caller scoping.
func (c *KeyorixCore) GetActivityFeed(ctx context.Context, userID uint, username string, page, pageSize int) (*ActivityFeed, error) {
	_ = userID
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}

	events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return &ActivityFeed{Items: []ActivityItem{}, Total: 0, Page: page, PageSize: pageSize}, nil
	}

	items := make([]ActivityItem, 0, len(events))
	for _, e := range events {
		items = append(items, mapAuditEventToActivity(e, username))
	}

	return &ActivityFeed{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

// getExpiringSecrets returns secrets expiring within 30 days OR already expired,
// sorted by expiration ascending (expired first, then soonest-expiring). The
// returned error (non-nil only when a page fails to load) signals that the
// result may be truncated — the caller (#394) must surface this as a degraded
// snapshot rather than silently treating a partial (or empty) list as complete.
func (c *KeyorixCore) getExpiringSecrets(ctx context.Context, username string) ([]ExpiringSecret, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	now := time.Now().UTC()
	cutoff := now.Add(30 * 24 * time.Hour)

	// Build environment name lookup once
	envNames := map[uint]string{}
	if envs, err := c.storage.ListEnvironments(ctx); err == nil {
		for _, e := range envs {
			envNames[e.ID] = e.Name
		}
	}

	// Page through every matching secret — a user with many secrets must not have
	// an expiring one silently dropped from the dashboard warning. The expiration
	// filter (expiration < cutoff) keeps the matched set small and does the
	// expired/expiring selection in the query.
	const pageSize = 200
	var result []ExpiringSecret
	var pageErr error
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			CreatedBy:     &username,
			ExpiresBefore: &cutoff,
			Page:          page,
			PageSize:      pageSize,
		})
		if err != nil {
			pageErr = err
			break
		}
		for _, s := range secrets {
			if s.Expiration == nil {
				continue // defensive; the filter already excludes nulls
			}
			exp := s.Expiration.UTC()
			envName := envNames[s.EnvironmentID]
			if envName == "" {
				envName = "unknown"
			}
			result = append(result, ExpiringSecret{
				ID:          s.ID,
				Name:        s.Name,
				Environment: envName,
				ExpiresAt:   exp,
				DaysLeft:    int(exp.Sub(now).Hours() / 24), // negative when expired
				Expired:     exp.Before(now),
			})
		}
		if len(secrets) < pageSize || int64(len(result)) >= total {
			break
		}
	}

	// Sort: expired first (most overdue first), then soonest-expiring
	sort.Slice(result, func(i, j int) bool {
		return result[i].ExpiresAt.Before(result[j].ExpiresAt)
	})

	return result, pageErr
}

// computeTrend calculates percentage change between previous and current values.
func computeTrend(prev, current float64) *StatTrend {
	if prev == 0 {
		if current == 0 {
			return nil
		}
		return &StatTrend{Value: 100, IsPositive: true}
	}
	change := ((current - prev) / prev) * 100
	if change == 0 {
		return nil
	}
	return &StatTrend{
		Value:      math.Round(math.Abs(change)*10) / 10,
		IsPositive: change > 0,
	}
}

// mapAuditEventToActivity maps a raw audit event to an ActivityItem.
//
// Type mapping — what the frontend receives:
//
//	secret.read     → "accessed"
//	secret.created  → "created"
//	secret.updated  → "updated"
//	secret.deleted  → "deleted"
//	secret.rotated  → "rotated"
//	secret.shared   → "shared"
//	share.revoked   → "share_revoked"
//	auth.login      → "login"      (secretName intentionally empty)
//	auth.logout     → "logout"     (secretName intentionally empty)
//	auth.*          → "auth"       (secretName intentionally empty)
//	<other>         → raw EventType, secretName empty
//
// SecretName is extracted from the Description for secret/share events.
// Auth and system events are not secret-related so secretName is left empty.
func mapAuditEventToActivity(e *models.AuditEvent, actor string) ActivityItem {
	var eventType, secretName string

	switch e.EventType {
	// Secret events — extract secret name from description
	case "secret.read":
		eventType = "accessed"
		secretName = extractSecretName(e.Description)
	case "secret.created":
		eventType = "created"
		secretName = extractSecretName(e.Description)
	case "secret.updated":
		eventType = "updated"
		secretName = extractSecretName(e.Description)
	case "secret.deleted":
		eventType = "deleted"
		secretName = extractSecretName(e.Description)
	case "secret.rotated":
		eventType = "rotated"
		secretName = extractSecretName(e.Description)
	case "secret.shared":
		eventType = "shared"
		secretName = extractSecretName(e.Description)
	case "share.revoked":
		eventType = "share_revoked"
		secretName = extractSecretName(e.Description)

	// Auth events — not secret-related, leave secretName empty
	case "auth.login":
		eventType = "login"
	case "auth.logout":
		eventType = "logout"
	case "auth.password_reset":
		eventType = "password_reset"

	// Fallback: pass event type through, no secret name
	default:
		eventType = e.EventType
	}

	return ActivityItem{
		ID:         e.ID,
		Type:       eventType,
		SecretName: secretName,
		Timestamp:  e.EventTime,
		Actor:      actor,
	}
}

// extractSecretName pulls the secret name from audit description strings.
// Descriptions follow the pattern: "User <actor> <verb> secret <name>"
// e.g. "User admin deleted secret test bulk 1" → "test bulk 1"
// Returns empty string if the pattern is not found.
func extractSecretName(description string) string {
	const marker = " secret "
	if idx := lastIndex(description, marker); idx >= 0 {
		return description[idx+len(marker):]
	}
	return ""
}

// lastIndex returns the index of the last occurrence of substr in s,
// or -1 if not present. Avoids importing strings package.
func lastIndex(s, substr string) int {
	if len(substr) == 0 {
		return len(s)
	}
	last := -1
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			last = i
		}
	}
	return last
}
