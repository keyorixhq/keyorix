// secret_access_stats.go — per-secret access statistics: a single, focused read of how
// much a secret is actually used (lifetime read count + a recent-window summary). It
// answers "is this secret used, and by whom lately?" directly, instead of cross-
// referencing the deployment-wide usage analytics, the per-user access log, and the
// composite risk score. Read-only; never returns the secret value.
package core

import (
	"context"
	"fmt"
	"time"
)

// SecretAccessStats summarises a secret's read activity. TotalReads is the durable
// lifetime counter (summed across versions, survives access-log retention); the *Window
// fields cover the last WindowDays of the (retained) access log.
type SecretAccessStats struct {
	SecretID      uint       `json:"secret_id"`
	TotalReads    int        `json:"total_reads"`
	Versions      int        `json:"versions"`
	WindowDays    int        `json:"window_days"`
	ReadsInWindow int        `json:"reads_in_window"`
	UniqueReaders int        `json:"unique_readers"`
	LastReadAt    *time.Time `json:"last_read_at,omitempty"`
}

// GetSecretAccessStats returns read statistics for a secret, enforcing secrets.read on
// the secret first. windowDays bounds the recent-activity summary (clamped to [1, 365],
// default 30 when <= 0). Lifetime TotalReads comes from the per-version read counters;
// the window fields are computed from the access log's "read" entries. No value is read.
func (c *KeyorixCore) GetSecretAccessStats(ctx context.Context, secretID, actorID uint, windowDays int) (*SecretAccessStats, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("secret ID is required")
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}

	switch {
	case windowDays <= 0:
		windowDays = 30
	case windowDays > 365:
		windowDays = 365
	}

	stats := &SecretAccessStats{SecretID: secretID, WindowDays: windowDays}

	// Lifetime reads — summed from the durable per-version counters.
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("get versions: %w", err)
	}
	stats.Versions = len(versions)
	for _, v := range versions {
		stats.TotalReads += v.ReadCount
	}

	// Recent window — from the access log's "read" entries.
	since := c.now().AddDate(0, 0, -windowDays)
	logs, err := c.storage.ListSecretAccessLogs(ctx, secretID, since)
	if err != nil {
		return nil, fmt.Errorf("list access logs: %w", err)
	}
	readers := map[string]struct{}{}
	for i := range logs {
		l := logs[i]
		if l.Action != "read" {
			continue
		}
		stats.ReadsInWindow++
		readers[l.AccessedBy] = struct{}{}
		if stats.LastReadAt == nil || l.AccessTime.After(*stats.LastReadAt) {
			t := l.AccessTime
			stats.LastReadAt = &t
		}
	}
	stats.UniqueReaders = len(readers)
	return stats, nil
}
