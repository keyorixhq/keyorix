package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetUsageReport returns a per-project usage report for the given window.
// If projectID is non-nil, the report is scoped to that project only.
// windowDays is clamped to [1, 365]; values outside that range default to 30.
func (c *KeyorixCore) GetUsageReport(ctx context.Context, windowDays int, projectID *uint) (*storage.UsageReport, error) {
	if windowDays <= 0 || windowDays > 365 {
		windowDays = 30
	}
	var projectIDs []uint
	if projectID != nil {
		projectIDs = []uint{*projectID}
	}
	stats, err := c.storage.GetProjectUsageStats(ctx, projectIDs, windowDays)
	if err != nil {
		return nil, err
	}
	if stats == nil {
		stats = []storage.ProjectUsageStat{}
	}
	return &storage.UsageReport{
		WindowDays:  windowDays,
		GeneratedAt: time.Now().UTC(),
		Projects:    stats,
	}, nil
}
