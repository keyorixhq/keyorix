package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Risk bands returned by ComputeSecretRiskScore.
const (
	RiskBandLow    = "low"
	RiskBandMedium = "medium"
	RiskBandHigh   = "high"
)

// SecretRiskFactor is one weighted contributor to a secret's risk score. Score
// is 0-100 (higher = riskier); the composite is the weight-weighted sum.
type SecretRiskFactor struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

// SecretRiskScore is a per-secret risk assessment combining expiry, rotation
// age, usage (read activity), and exposure (how many principals can read it).
type SecretRiskScore struct {
	SecretID   uint               `json:"secret_id"`
	SecretName string             `json:"secret_name"`
	Score      int                `json:"score"` // 0-100 weighted composite (higher = riskier)
	Band       string             `json:"band"`  // low | medium | high
	Factors    []SecretRiskFactor `json:"factors"`
}

func riskBand(score int) string {
	switch {
	case score >= 67:
		return RiskBandHigh
	case score >= 34:
		return RiskBandMedium
	default:
		return RiskBandLow
	}
}

// ComputeSecretRiskScore builds a per-secret risk score. Factor weights:
// expiry 30%, rotation age 30%, usage 20%, exposure 20%.
func (c *KeyorixCore) ComputeSecretRiskScore(ctx context.Context, secretID uint) (*SecretRiskScore, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	now := c.now()

	expScore, expDetail := expiryRisk(secret.Expiration, now)
	rotScore, rotDetail := rotationRisk(secret.LastRotatedAt, secret.CreatedAt, now)
	usageScore, usageDetail := usageRisk(c.countReads(ctx, secretID, now.AddDate(0, 0, -30)))
	expoScore, expoDetail := exposureRisk(c.countPrincipals(ctx, secret))

	factors := []SecretRiskFactor{
		{Key: "expiry", Label: "Expiry", Score: expScore, Weight: 0.30, Detail: expDetail},
		{Key: "rotation", Label: "Rotation age", Score: rotScore, Weight: 0.30, Detail: rotDetail},
		{Key: "usage", Label: "Usage", Score: usageScore, Weight: 0.20, Detail: usageDetail},
		{Key: "exposure", Label: "Exposure", Score: expoScore, Weight: 0.20, Detail: expoDetail},
	}

	var composite float64
	for _, f := range factors {
		composite += float64(f.Score) * f.Weight
	}
	score := int(composite + 0.5)

	return &SecretRiskScore{
		SecretID:   secret.ID,
		SecretName: secret.Name,
		Score:      score,
		Band:       riskBand(score),
		Factors:    factors,
	}, nil
}

func expiryRisk(exp *time.Time, now time.Time) (int, string) {
	if exp == nil {
		return 40, "No expiration set"
	}
	days := int(exp.Sub(now).Hours() / 24)
	switch {
	case days < 0:
		return 100, fmt.Sprintf("Expired %d day(s) ago", -days)
	case days <= 7:
		return 80, fmt.Sprintf("Expires in %d day(s)", days)
	case days <= 30:
		return 50, fmt.Sprintf("Expires in %d day(s)", days)
	default:
		return 10, fmt.Sprintf("Expires in %d day(s)", days)
	}
}

func rotationRisk(lastRotated *time.Time, created, now time.Time) (int, string) {
	basis, verb := created, "created"
	if lastRotated != nil {
		basis, verb = *lastRotated, "rotated"
	}
	days := int(now.Sub(basis).Hours() / 24)

	var score int
	switch {
	case days < 30:
		score = 10
	case days < 90:
		score = 30
	case days < 180:
		score = 60
	case days < 365:
		score = 80
	default:
		score = 100
	}

	never := ""
	if lastRotated == nil {
		never = " (never rotated)"
		if days >= 90 && score < 100 {
			score += 10
		}
	}
	return score, fmt.Sprintf("Last %s %d day(s) ago%s", verb, days, never)
}

func usageRisk(reads int) (int, string) {
	switch {
	case reads == 0:
		return 80, "No reads in the last 30 days"
	case reads <= 5:
		return 40, fmt.Sprintf("%d read(s) in the last 30 days", reads)
	default:
		return 10, fmt.Sprintf("%d reads in the last 30 days", reads)
	}
}

func exposureRisk(principals int) (int, string) {
	switch {
	case principals <= 1:
		return 10, "Only the owner has access"
	case principals <= 5:
		return 30, fmt.Sprintf("%d principals have access", principals)
	case principals <= 15:
		return 60, fmt.Sprintf("%d principals have access", principals)
	default:
		return 90, fmt.Sprintf("%d principals have access", principals)
	}
}

func (c *KeyorixCore) countReads(ctx context.Context, secretID uint, since time.Time) int {
	logs, err := c.storage.ListSecretAccessLogs(ctx, secretID, since)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range logs {
		if l.Action == "read" {
			n++
		}
	}
	return n
}

// countPrincipals counts the distinct users that can read a secret: the owner
// plus direct share recipients plus the members of any group it is shared with.
func (c *KeyorixCore) countPrincipals(ctx context.Context, secret *models.SecretNode) int {
	principals := map[uint]struct{}{secret.OwnerID: {}}
	shares, err := c.storage.ListSharesBySecret(ctx, secret.ID)
	if err != nil {
		return len(principals)
	}
	for _, sh := range shares {
		if sh.IsGroup {
			members, err := c.storage.ListGroupMembers(ctx, sh.RecipientID)
			if err != nil {
				continue
			}
			for _, m := range members {
				principals[m.ID] = struct{}{}
			}
		} else {
			principals[sh.RecipientID] = struct{}{}
		}
	}
	return len(principals)
}
