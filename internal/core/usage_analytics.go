package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	defaultUsageWindowDays   = 30
	defaultMostAccessedLimit = 10
	maxMostAccessedLimit     = 100
	// maxUsageWindowDays bounds the caller-supplied lookback window (#G44) — an
	// unbounded value passed to AddDate can produce a pathological cutoff time
	// and, more importantly, no longer matches "recent usage analytics" intent.
	maxUsageWindowDays = 3650 // 10 years
)

// MostAccessedSecrets returns the most-read secrets (optionally scoped to a
// project) over the last `days` (default 30), capped at `limit` (default 10,
// max 100). Backs the usage-analytics dashboard's "most accessed" ranking.
func (c *KeyorixCore) MostAccessedSecrets(ctx context.Context, projectID *uint, days, limit int) ([]storage.SecretUsageStat, error) {
	if days <= 0 {
		days = defaultUsageWindowDays
	}
	if days > maxUsageWindowDays {
		days = maxUsageWindowDays
	}
	if limit <= 0 {
		limit = defaultMostAccessedLimit
	}
	if limit > maxMostAccessedLimit {
		limit = maxMostAccessedLimit
	}
	since := c.now().AddDate(0, 0, -days)
	stats, err := c.storage.MostAccessedSecrets(ctx, projectID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to compute most-accessed secrets: %w", err)
	}
	return stats, nil
}

// UnusedSecrets returns secrets (optionally scoped to a project) with no read
// in the last `days` (default 30), including never-read secrets. Powers the
// "find & retire dead secrets" view.
func (c *KeyorixCore) UnusedSecrets(ctx context.Context, projectID *uint, days int) ([]storage.UnusedSecretStat, error) {
	if days <= 0 {
		days = defaultUsageWindowDays
	}
	if days > maxUsageWindowDays {
		days = maxUsageWindowDays
	}
	cutoff := c.now().AddDate(0, 0, -days)
	stats, err := c.storage.UnusedSecrets(ctx, projectID, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to compute unused secrets: %w", err)
	}
	return stats, nil
}
