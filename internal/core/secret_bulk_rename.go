// secret_bulk_rename.go — bulk rename of secrets toward naming-policy conformance. The
// naming policy ([[secret_name_policy]]) is enforced only at create time, so the
// conformance report ([[secret_name_conformance]]) surfaces live secrets whose names
// have fallen out of conformance — this is the remediation: rename them in one call.
// Each requested new name must itself satisfy the current policy (you can only rename
// TOWARD conformance, never into a fresh violation) and must not collide with a sibling.
// dry-run validates and reports what WOULD change without touching anything. Never reads
// or changes a secret's value. Project-scoped (route-gated secrets.write). Parallels the
// bulk extend-expiring / reassign-owner / suspend-all operations.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Rename outcome statuses.
const (
	renameStatusRenamed     = "renamed"      // applied
	renameStatusWouldRename = "would_rename" // dry-run: passed all checks, not applied
	renameStatusSkipped     = "skipped"      // failed a precondition; reason carries why
)

// SecretRename is one requested rename: the target secret's ID and the new name.
type SecretRename struct {
	ID      uint   `json:"id"`
	NewName string `json:"new_name"`
}

// SecretRenameOutcome reports what happened (or, in dry-run, would happen) for one
// requested rename. Skipped outcomes carry the reason.
type SecretRenameOutcome struct {
	ID      uint   `json:"id"`
	OldName string `json:"old_name,omitempty"`
	NewName string `json:"new_name"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// BulkRenameReport summarizes a bulk-rename run. DryRun=true means nothing was changed;
// Renamed counts the secrets that were (or, in dry-run, would be) renamed.
type BulkRenameReport struct {
	DryRun   bool                  `json:"dry_run"`
	Renamed  int                   `json:"renamed"`
	Skipped  int                   `json:"skipped"`
	Outcomes []SecretRenameOutcome `json:"outcomes"`
}

// BulkRenameSecrets renames each requested secret to its new name, within a single
// project. For every entry it enforces, in order: the secret exists and belongs to THIS
// project (cross-project guard — a project-scoped caller can never reach another
// project's secret), it is a secret and not a folder, the name actually changes, the new
// name satisfies the current naming policy (rename toward conformance only), and the new
// name does not collide with a sibling in the same environment. An entry failing any
// check is skipped with a reason; the rest proceed (best-effort, like the other bulk
// ops). With dryRun the checks run but nothing is persisted. Each applied rename is
// audited as secret.updated with a name before/after diff. Never reads a secret value.
func (c *KeyorixCore) BulkRenameSecrets(ctx context.Context, projectID uint, renames []SecretRename, dryRun bool, actor string, actorID uint, ip, ua string) (*BulkRenameReport, error) { // NOSONAR -- domain-driven parameter count; cognitive complexity 28, suppress go:S3776
	if projectID == 0 || actorID == 0 {
		return nil, fmt.Errorf("project ID and actor ID are required")
	}
	if len(renames) == 0 {
		return nil, fmt.Errorf("at least one rename is required")
	}

	report := &BulkRenameReport{DryRun: dryRun, Outcomes: make([]SecretRenameOutcome, 0, len(renames))}

	skip := func(id uint, oldName, newName, reason string) {
		report.Outcomes = append(report.Outcomes, SecretRenameOutcome{
			ID: id, OldName: oldName, NewName: newName, Status: renameStatusSkipped, Reason: reason,
		})
		report.Skipped++
	}

	for _, rn := range renames {
		newName := strings.TrimSpace(rn.NewName)
		if rn.ID == 0 {
			skip(rn.ID, "", newName, "secret ID is required")
			continue
		}
		if newName == "" {
			skip(rn.ID, "", "", "new name is empty")
			continue
		}

		// #G14: "not found", "belongs to another project", and "not authorized" are
		// collapsed into one uniform denial below — a distinct message per case
		// would let a caller enumerate secret IDs that exist in OTHER projects
		// (or that they can't individually act on) from the shape of the failure
		// alone, even though they're plainly a real, existing secret.
		secret, err := c.storage.GetSecret(ctx, rn.ID)
		if err != nil || secret == nil || secret.ProjectID != projectID {
			skip(rn.ID, "", newName, "secret not found")
			continue
		}
		// Re-check per-secret write authorization (owner/share). The project-wide
		// secrets.write route gate is not sufficient on its own — the single-secret PUT
		// path enforces this, so the bulk op must not let a caller rename a secret they
		// can't update individually.
		if _, perr := c.EnforceSecretWritePermission(ctx, secret.ID, actorID); perr != nil {
			skip(rn.ID, "", newName, "secret not found")
			continue
		}
		if !secret.IsSecret {
			skip(rn.ID, secret.Name, newName, "not a secret (folder nodes have no governed name)")
			continue
		}
		if secret.Name == newName {
			skip(rn.ID, secret.Name, newName, "name unchanged")
			continue
		}
		// Rename toward conformance only — refuse a new name that itself violates the
		// current policy. (With no policy configured this always passes.)
		if verr := c.validateSecretName(newName); verr != nil {
			skip(rn.ID, secret.Name, newName, verr.Error())
			continue
		}
		// Name uniqueness is scoped to (name, project, environment) — don't collide with
		// a sibling already holding the target name.
		if existing, err := c.storage.GetSecretByName(ctx, newName, secret.ProjectID, secret.EnvironmentID); err == nil && existing != nil && existing.ID != secret.ID {
			skip(rn.ID, secret.Name, newName, "a secret with that name already exists in this environment")
			continue
		}

		if dryRun {
			report.Outcomes = append(report.Outcomes, SecretRenameOutcome{
				ID: rn.ID, OldName: secret.Name, NewName: newName, Status: renameStatusWouldRename,
			})
			report.Renamed++
			continue
		}

		oldName := secret.Name
		secret.Name = newName
		if _, err := c.storage.UpdateSecret(ctx, secret); err != nil {
			skip(rn.ID, oldName, newName, "storage error")
			continue
		}
		c.LogSecretUpdatedWithDiff(ctx, actorID, secret.ID, projectID, actor, newName, ip, ua, buildNameRenameDiff(oldName, newName))
		report.Outcomes = append(report.Outcomes, SecretRenameOutcome{
			ID: rn.ID, OldName: oldName, NewName: newName, Status: renameStatusRenamed,
		})
		report.Renamed++
	}
	return report, nil
}

// buildNameRenameDiff renders the audit before/after for a name change. Never carries a
// value — only the renamed names.
func buildNameRenameDiff(oldName, newName string) string {
	b, err := json.Marshal(map[string]map[string]string{
		"name": {"before": oldName, "after": newName},
	})
	if err != nil {
		return ""
	}
	return string(b)
}
