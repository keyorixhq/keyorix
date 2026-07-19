// hygiene_trends.go — 30/60/90-day credential-hygiene trend data.
//
// Exposes per-day counts of stale PATs (active but unused > 30 days), expired
// PATs (not yet revoked), and stale machine credentials (no credential used in
// 30 days). Today's point is always computed live from the current table state;
// historical points come from HygieneTrendSnapshot rows persisted by
// RecordHygieneTrendPoint (a daily scheduler job or the on-demand admin endpoint).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// stalePATWindow is the inactivity window after which a non-expired PAT is
// considered stale (mirrors the defaultPATStaleAfter definition in pat_hygiene.go).
const stalePATWindow = 30 * 24 * time.Hour

// staleMachineWindow is the inactivity window after which an active machine
// identity is considered stale (no credential used in 30 days).
const staleMachineWindow = 30 * 24 * time.Hour

// HygieneTrendPoint holds hygiene counts for one calendar day.
type HygieneTrendPoint struct {
	Date          time.Time `json:"date"`
	StalePATs     int       `json:"stale_pats"`     // active PATs unused > 30 days
	ExpiredPATs   int       `json:"expired_pats"`   // PATs where ExpiresAt < now, not revoked
	StaleMachines int       `json:"stale_machines"` // active machine identities with no recent credential use
	TotalPATs     int       `json:"total_pats"`
	TotalMachines int       `json:"total_machines"`
}

// HygieneTrendsReport is the response for GET /compliance/credential-trends.
type HygieneTrendsReport struct {
	Days   int                 `json:"days"`
	Points []HygieneTrendPoint `json:"points"`
}

// GetHygieneTrends returns per-day credential hygiene counts for the last
// `days` days (valid values: 30, 60, 90; anything else defaults to 30).
//
// Today's point is always derived from the current table state; historical
// points come from persisted HygieneTrendSnapshot rows (written by
// RecordHygieneTrendPoint). Days with no snapshot (i.e. before the first
// RecordHygieneTrendPoint call) are omitted from Points.
func (k *KeyorixCore) GetHygieneTrends(ctx context.Context, days int) (*HygieneTrendsReport, error) {
	if days != 30 && days != 60 && days != 90 {
		days = 30
	}

	// Always compute today's live point.
	today, err := k.computeHygieneTrendPoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute today's hygiene trend: %w", err)
	}

	// Fetch historical snapshots for the window.
	snaps, err := k.storage.ListHygieneTrendSnapshots(ctx, days)
	if err != nil {
		return nil, fmt.Errorf("list hygiene trend snapshots: %w", err)
	}

	todayDate := truncateToDay(today.Date)

	// Build the points list: today first, then historical rows (excluding any
	// row whose date matches today — the live computation supersedes it).
	points := []HygieneTrendPoint{*today}
	for _, s := range snaps {
		if truncateToDay(s.SnapshotDate).Equal(todayDate) {
			continue
		}
		points = append(points, HygieneTrendPoint{
			Date:          s.SnapshotDate,
			StalePATs:     s.StalePATs,
			ExpiredPATs:   s.ExpiredPATs,
			StaleMachines: s.StaleMachines,
			TotalPATs:     s.TotalPATs,
			TotalMachines: s.TotalMachines,
		})
	}

	return &HygieneTrendsReport{Days: days, Points: points}, nil
}

// RecordHygieneTrendPoint computes today's credential-hygiene counts and
// persists them as a HygieneTrendSnapshot for future trend queries. Returns
// the point that was saved.
func (k *KeyorixCore) RecordHygieneTrendPoint(ctx context.Context) (*HygieneTrendPoint, error) {
	point, err := k.computeHygieneTrendPoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute hygiene trend point: %w", err)
	}

	snap := &models.HygieneTrendSnapshot{
		StalePATs:     point.StalePATs,
		ExpiredPATs:   point.ExpiredPATs,
		StaleMachines: point.StaleMachines,
		TotalPATs:     point.TotalPATs,
		TotalMachines: point.TotalMachines,
		SnapshotDate:  truncateToDay(point.Date),
	}
	if err := k.storage.SaveHygieneTrendSnapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("save hygiene trend snapshot: %w", err)
	}
	return point, nil
}

// computeHygieneTrendPoint derives the current hygiene counts from the live
// table state. Called for today's point by both GetHygieneTrends and
// RecordHygieneTrendPoint.
func (k *KeyorixCore) computeHygieneTrendPoint(ctx context.Context) (*HygieneTrendPoint, error) {
	now := k.now()
	staleCutoff := now.Add(-stalePATWindow)
	machineStaleCutoff := now.Add(-staleMachineWindow)

	stalePATs, err := k.storage.CountStalePATs(ctx, staleCutoff)
	if err != nil {
		return nil, fmt.Errorf("count stale PATs: %w", err)
	}

	expiredPATs, err := k.storage.CountExpiredPATs(ctx)
	if err != nil {
		return nil, fmt.Errorf("count expired PATs: %w", err)
	}

	staleMachines, err := k.storage.CountStaleMachineCredentials(ctx, machineStaleCutoff)
	if err != nil {
		return nil, fmt.Errorf("count stale machine credentials: %w", err)
	}

	// Total PATs (non-revoked) and total active machine identities for context.
	allPATs, err := k.storage.ListActivePersonalAccessTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active PATs: %w", err)
	}
	allMachines, err := k.storage.ListAllMachineIdentities(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all machine identities: %w", err)
	}
	totalMachines := 0
	for _, m := range allMachines {
		if m.State == "active" {
			totalMachines++
		}
	}

	return &HygieneTrendPoint{
		Date:          now,
		StalePATs:     stalePATs,
		ExpiredPATs:   expiredPATs,
		StaleMachines: staleMachines,
		TotalPATs:     len(allPATs),
		TotalMachines: totalMachines,
	}, nil
}

// truncateToDay returns t truncated to UTC midnight.
func truncateToDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
