// classification.go — data classification of secrets (ISO 27001 A.5.12 classification
// of information / A.5.13 labelling). Each secret carries an optional sensitivity
// label; the label drives the classification posture and lets a reviewer find the
// high-sensitivity secrets. "" means unclassified.
//
// KNOWN LIMITATION — classification is a label, not a control: setting a secret (or
// dynamic-secret config, or machine identity)'s Classification to "restricted" does
// NOT currently change how it is treated at read time, in RBAC, in rate limiting, or
// anywhere else in the request path — it is purely informational metadata surfaced in
// the compliance posture / audit views. Do not assume a "restricted" secret gets any
// additional gating a "public" one doesn't; if that's the requirement, it must be
// implemented as an explicit policy check at the relevant enforcement point (there is
// none today). This is a deliberate scope decision, not an oversight — enforcement is
// a materially larger feature (would need a policy engine deciding what "restricted"
// actually restricts: extra approval? MFA step-up? narrower RBAC? all of the above are
// plausible and none is implemented).
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Classification levels, lowest → highest sensitivity. "" (unclassified) is also
// a valid stored state (not yet labelled).
const (
	ClassificationPublic       = "public"
	ClassificationInternal     = "internal"
	ClassificationConfidential = "confidential"
	ClassificationRestricted   = "restricted"
)

// ClassificationLevels is the ordered set of valid (non-empty) labels.
var ClassificationLevels = []string{
	ClassificationPublic, ClassificationInternal, ClassificationConfidential, ClassificationRestricted,
}

// IsValidClassification reports whether level is "" (unclassified) or a known label.
func IsValidClassification(level string) bool {
	if level == "" {
		return true
	}
	for _, l := range ClassificationLevels {
		if l == level {
			return true
		}
	}
	return false
}

// ClassifySecret sets (or clears, with "") a secret's data-classification label and
// audits the change as a secret.updated event with a before/after diff. actorID is
// the acting user; username is for the audit description.
func (c *KeyorixCore) ClassifySecret(ctx context.Context, actorID uint, username string, secretID uint, level string) (*models.SecretNode, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil),
			"classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Classification == level {
		return secret, nil // no-op
	}
	old := secret.Classification
	secret.Classification = level
	updated, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.LogSecretUpdatedWithDiff(ctx, actorID, secretID, secret.ProjectID, username, secret.Name, "", "", diff)
	return updated, nil
}
