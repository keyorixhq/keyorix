// project_health.go — per-project secret health summary.
//
// GetProjectHealthSummary aggregates ComputeSecretRiskScoresBatch across all
// secrets in a project and returns band counts plus the top-N riskiest secrets.
package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ProjectHealthSummary is the result of GetProjectHealthSummary.
type ProjectHealthSummary struct {
	ProjectID       uint               `json:"project_id"`
	TotalSecrets    int                `json:"total_secrets"`
	HighRiskCount   int                `json:"high_risk_count"`
	MediumRiskCount int                `json:"medium_risk_count"`
	LowRiskCount    int                `json:"low_risk_count"`
	TopRiskSecrets  []*SecretRiskScore `json:"secrets"`
	// Truncated is true when the project has more secrets than the bounded
	// PageSize below fetched — TotalSecrets and the risk-band counts then
	// reflect only the fetched sample, not the project's true secret count
	// (#G24: previously TotalSecrets silently reported the truncated sample
	// size as if it were the real total).
	Truncated bool `json:"truncated"`
}

const (
	defaultHealthLimit = 20
	maxHealthLimit     = 100
)

// GetProjectHealthSummary lists all secrets in projectID, scores them in batch,
// counts by risk band, and returns the top `limit` secrets sorted by Score desc.
// limit is clamped: if <= 0 or > 100 it defaults to 20.
func (c *KeyorixCore) GetProjectHealthSummary(ctx context.Context, projectID uint, limit int) (*ProjectHealthSummary, error) {
	if limit <= 0 || limit > maxHealthLimit {
		limit = defaultHealthLimit
	}

	// Fetch ALL secrets for the project (no paging — admin function).
	trueVal := true
	secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		IsSecret:  &trueVal,
		PageSize:  maxHealthLimit * 10, // generous upper bound; health is a bounded admin view
		Page:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	truncated := int64(len(secrets)) < total

	// Collect all IDs in one pass.
	ids := make([]uint, 0, len(secrets))
	for _, s := range secrets {
		ids = append(ids, s.ID)
	}

	// Score the whole batch with one set of queries.
	scoreMap, err := c.ComputeSecretRiskScoresBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("compute risk scores: %w", err)
	}

	// Build the ordered slice and band counts.
	all := make([]*SecretRiskScore, 0, len(scoreMap))
	var highN, medN, lowN int
	for _, s := range scoreMap {
		all = append(all, s)
		switch s.Band {
		case RiskBandHigh:
			highN++
		case RiskBandMedium:
			medN++
		default:
			lowN++
		}
	}

	// Sort by Score descending; break ties by SecretID for determinism.
	sort.Slice(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		return all[i].SecretID < all[j].SecretID
	})

	// Return only the top `limit`.
	top := all
	if len(top) > limit {
		top = top[:limit]
	}

	return &ProjectHealthSummary{
		ProjectID:       projectID,
		TotalSecrets:    int(total),
		HighRiskCount:   highN,
		MediumRiskCount: medN,
		LowRiskCount:    lowN,
		TopRiskSecrets:  top,
		Truncated:       truncated,
	}, nil
}
