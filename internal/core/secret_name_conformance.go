// secret_name_conformance.go — a project's secret-name conformance report against the
// CURRENT naming policy ([[secret_name_policy]]). The naming convention is enforced only
// at create time, so a name can fall out of conformance after the policy is added or
// tightened (existing names are never retroactively checked). This read-only scan finds
// the live secrets whose names now violate the policy so an operator can rename them.
// Never reads a secret value; mirrors [[secret_inventory]] (project-scoped secrets.read).
package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// SecretNameViolation is one live secret whose name fails the current naming policy.
type SecretNameViolation struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification,omitempty"`
	EnvironmentID  uint   `json:"environment_id"`
	Reason         string `json:"reason"`
}

// SecretNameConformanceReport is a project's secret-name conformance summary against the
// current naming policy. PolicyEnabled=false means no naming policy is configured, so
// there are no violations by definition and the scan is skipped.
type SecretNameConformanceReport struct {
	PolicyEnabled bool                  `json:"policy_enabled"`
	Pattern       string                `json:"pattern,omitempty"`
	MaxLength     int                   `json:"max_length,omitempty"`
	TotalSecrets  int                   `json:"total_secrets"`
	Violations    []SecretNameViolation `json:"violations"`
	// Truncated reports whether secretInventoryMaxRows was hit, i.e. the project
	// has more secrets than were scanned — TotalSecrets/Violations then reflect
	// only the scanned sample (#G24: matches the deployment-wide sibling's own
	// Truncated field, which this per-project report previously lacked).
	Truncated bool `json:"truncated,omitempty"`
}

// SecretNameConformance scans every live secret in the project (folders excluded) and
// lists those whose name fails the current naming policy, each with the violation
// reason (the exact message create-time enforcement would produce). Reuses the same
// validateSecretName check so the report can never drift from enforcement. Never reads
// a value. Bounded to secretInventoryMaxRows; sorted by name.
func (c *KeyorixCore) SecretNameConformance(ctx context.Context, projectID uint) (*SecretNameConformanceReport, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}

	report := &SecretNameConformanceReport{
		PolicyEnabled: c.secretNamePolicy.Enabled,
		Pattern:       c.secretNamePolicy.Pattern,
		MaxLength:     c.secretNamePolicy.MaxLength,
		Violations:    []SecretNameViolation{},
	}
	// No policy configured → nothing can be in violation; skip the scan entirely.
	if !c.secretNamePolicy.Enabled {
		return report, nil
	}

	secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID, Page: 1, PageSize: secretInventoryMaxRows,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	report.Truncated = int64(len(secrets)) < total

	for _, s := range secrets {
		if !s.IsSecret {
			continue // skip folder nodes — only assets have governed names
		}
		report.TotalSecrets++
		if verr := c.validateSecretName(s.Name); verr != nil {
			report.Violations = append(report.Violations, SecretNameViolation{
				ID:             s.ID,
				Name:           s.Name,
				Type:           s.Type,
				Classification: s.Classification,
				EnvironmentID:  s.EnvironmentID,
				Reason:         verr.Error(),
			})
		}
	}

	sort.Slice(report.Violations, func(i, j int) bool {
		return report.Violations[i].Name < report.Violations[j].Name
	})
	return report, nil
}
