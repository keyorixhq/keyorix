package core

import (
	"context"
	"math"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ExpiringSecret represents a secret that is expiring soon.
type ExpiringSecret struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Environment string    `json:"environment"`
	ExpiresAt   time.Time `json:"expiresAt"`
	DaysLeft    int       `json:"daysLeft"`
}

// StatTrend contains trend data for a dashboard stat.
type StatTrend struct {
	Value      float64 `json:"value"`      // % change vs previous snapshot
	IsPositive bool    `json:"isPositive"` // true = grew, false = shrank
}

// DashboardStats contains summary statistics for the dashboard.
type DashboardStats struct {
	TotalSecrets        int64            `json:"totalSecrets"`
	SharedSecrets       int              `json:"sharedSecrets"`
	SecretsSharedWithMe int              `json:"secretsSharedWithMe"`
	TotalSecretsTrend   *StatTrend       `json:"totalSecretsTrend,omitempty"`
	SharedSecretsTrend  *StatTrend       `json:"sharedSecretsTrend,omitempty"`
	SharedWithMeTrend   *StatTrend       `json:"sharedWithMeTrend,omitempty"`
	ExpiringSecrets     []ExpiringSecret `json:"expiringSecrets,omitempty"`
	RecentActivity      []ActivityItem   `json:"recentActivity"`
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
	_, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &username,
		Page:      1,
		PageSize:  1,
	})
	if err != nil {
		total = 0
	}

	outgoing, err := c.storage.ListSharesByOwner(ctx, userID)
	sharedSecrets := 0
	if err == nil {
		sharedSecrets = len(outgoing)
	}

	incoming, err := c.storage.ListSharesByUser(ctx, userID)
	sharedWithMe := 0
	if err == nil {
		sharedWithMe = len(incoming)
	}

	uid := userID
	events, _, _ := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		UserID:   &uid,
		Page:     1,
		PageSize: 5,
	})
	recent := make([]ActivityItem, 0, len(events))
	for _, e := range events {
		recent = append(recent, mapAuditEventToActivity(e, username))
	}

	expiringSecrets := c.getExpiringSecrets(ctx, username)

	stats := &DashboardStats{
		TotalSecrets:        total,
		SharedSecrets:       sharedSecrets,
		SecretsSharedWithMe: sharedWithMe,
		RecentActivity:      recent,
		ExpiringSecrets:     expiringSecrets,
	}

	prev, err := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if err == nil && prev != nil {
		stats.TotalSecretsTrend = computeTrend(float64(prev.TotalSecrets), float64(total))
		stats.SharedSecretsTrend = computeTrend(float64(prev.SharedSecrets), float64(sharedSecrets))
		stats.SharedWithMeTrend = computeTrend(float64(prev.SecretsSharedWithMe), float64(sharedWithMe))
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

// GetActivityFeed returns a paginated activity feed for the given user.
func (c *KeyorixCore) GetActivityFeed(ctx context.Context, userID uint, username string, page, pageSize int) (*ActivityFeed, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}

	uid := userID
	events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		UserID:   &uid,
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

// getExpiringSecrets returns secrets owned by the user expiring within 30 days.
func (c *KeyorixCore) getExpiringSecrets(ctx context.Context, username string) []ExpiringSecret {
	now := time.Now().UTC()
	cutoff := now.Add(30 * 24 * time.Hour)

	secrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &username,
		Page:      1,
		PageSize:  100,
	})
	if err != nil {
		return nil
	}

	var expiring []ExpiringSecret
	for _, s := range secrets {
		if s.Expiration == nil {
			continue
		}
		exp := s.Expiration.UTC()
		if exp.After(now) && exp.Before(cutoff) {
			daysLeft := int(exp.Sub(now).Hours() / 24)
			envName := "unknown"
			if envs, err := c.storage.ListEnvironments(ctx); err == nil {
				for _, e := range envs {
					if e.ID == s.EnvironmentID {
						envName = e.Name
						break
					}
				}
			}
			expiring = append(expiring, ExpiringSecret{
				ID:          s.ID,
				Name:        s.Name,
				Environment: envName,
				ExpiresAt:   exp,
				DaysLeft:    daysLeft,
			})
		}
	}
	return expiring
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
