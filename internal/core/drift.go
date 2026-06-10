package core

import (
	"context"
	"fmt"
	"sort"
)

// Drift status values for a single key across a project's environments.
const (
	DriftStatusConsistent   = "consistent"      // present in every environment, settings agree
	DriftStatusMissingSome  = "missing_in_some" // present in some environments, absent in others
	DriftStatusMetadataOnly = "metadata_drift"  // present everywhere, but settings differ
)

// DriftEnvironment is one environment column in the drift report.
type DriftEnvironment struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// DriftKey is one secret key's posture across the project's environments.
type DriftKey struct {
	Name string `json:"name"`
	// PresentIn / MissingFrom are environment ids (subsets of the report's
	// Environments). MissingFrom is empty when the key exists everywhere.
	PresentIn   []uint `json:"present_in"`
	MissingFrom []uint `json:"missing_from"`
	// Status is one of the DriftStatus* values.
	Status string `json:"status"`
	// DriftFields names the settings that differ across the environments that DO
	// have this key (subset of "type", "expiration", "max_reads"). Empty unless
	// the settings diverge.
	DriftFields []string `json:"drift_fields,omitempty"`
}

// DriftSummary is the headline tally for the drift report.
type DriftSummary struct {
	EnvironmentCount int `json:"environment_count"`
	TotalKeys        int `json:"total_keys"`
	ConsistentKeys   int `json:"consistent_keys"`
	MissingInSome    int `json:"missing_in_some"`
	MetadataDrift    int `json:"metadata_drift"`
}

// ProjectDrift is the cross-environment drift report for a project: the
// environment columns, the keys that drift (consistent keys are summarised, not
// listed), and a summary tally.
type ProjectDrift struct {
	ProjectID    uint               `json:"project_id"`
	Environments []DriftEnvironment `json:"environments"`
	// DriftedKeys lists only keys that are NOT fully consistent (missing in some
	// environment, or present everywhere but with diverging settings), name-sorted.
	DriftedKeys []DriftKey   `json:"drifted_keys"`
	Summary     DriftSummary `json:"summary"`
}

// DetectProjectDrift compares secret keys across all of a project's
// environments and reports the keys that drift — present in some environments
// but not others, or present everywhere with diverging settings (type /
// expiration / max-reads). No secret values are read. With fewer than two
// environments no drift is possible, so the report is empty. Backs
// GET /api/v1/projects/{id}/drift.
func (c *KeyorixCore) DetectProjectDrift(ctx context.Context, projectID uint) (*ProjectDrift, error) {
	envs, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list environments for drift: %w", err)
	}

	report := &ProjectDrift{ProjectID: projectID}
	envIDs := make([]uint, 0, len(envs))
	for _, e := range envs {
		report.Environments = append(report.Environments, DriftEnvironment{ID: e.ID, Name: e.Name})
		envIDs = append(envIDs, e.ID)
	}
	report.Summary.EnvironmentCount = len(envs)

	rows, err := c.storage.ListProjectSecretsForDrift(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets for drift: %w", err)
	}

	// Pivot rows into name -> (envID -> cell). A name may legitimately appear once
	// per environment; duplicates within one environment collapse to the last.
	byName := map[string]map[uint]driftCell{}
	names := make([]string, 0)
	for _, r := range rows {
		if _, ok := byName[r.Name]; !ok {
			byName[r.Name] = map[uint]driftCell{}
			names = append(names, r.Name)
		}
		byName[r.Name][r.EnvironmentID] = driftCell{typ: r.Type, hasExpiration: r.HasExpiration, hasMaxReads: r.HasMaxReads}
	}
	sort.Strings(names)

	report.Summary.TotalKeys = len(names)

	for _, name := range names {
		cells := byName[name]

		presentIn := make([]uint, 0, len(cells))
		missingFrom := make([]uint, 0)
		for _, id := range envIDs { // iterate in environment order for stable output
			if _, ok := cells[id]; ok {
				presentIn = append(presentIn, id)
			} else {
				missingFrom = append(missingFrom, id)
			}
		}

		driftFields := metadataDriftFields(cells)

		// Fully consistent: present in every environment AND no setting diverges.
		if len(missingFrom) == 0 && len(driftFields) == 0 {
			report.Summary.ConsistentKeys++
			continue
		}

		key := DriftKey{
			Name:        name,
			PresentIn:   presentIn,
			MissingFrom: missingFrom,
			DriftFields: driftFields,
		}
		if len(missingFrom) > 0 {
			key.Status = DriftStatusMissingSome
			report.Summary.MissingInSome++
		} else {
			key.Status = DriftStatusMetadataOnly
			report.Summary.MetadataDrift++
		}
		report.DriftedKeys = append(report.DriftedKeys, key)
	}

	return report, nil
}

// driftCell is one secret's drift-relevant settings within a single environment.
type driftCell struct {
	typ           string
	hasExpiration bool
	hasMaxReads   bool
}

// metadataDriftFields reports which settings differ across the environments that
// have a given key. Only the environments that actually hold the key are
// compared, so a key missing from an environment is a presence issue, not a
// metadata one. Returns a sorted subset of {"type","expiration","max_reads"}.
func metadataDriftFields(cells map[uint]driftCell) []string {
	if len(cells) < 2 {
		return nil
	}
	var first driftCell
	var typeDrift, expDrift, maxDrift bool
	seen := false
	for _, c := range cells {
		if !seen {
			first = c
			seen = true
			continue
		}
		if c.typ != first.typ {
			typeDrift = true
		}
		if c.hasExpiration != first.hasExpiration {
			expDrift = true
		}
		if c.hasMaxReads != first.hasMaxReads {
			maxDrift = true
		}
	}
	fields := make([]string, 0, 3)
	if typeDrift {
		fields = append(fields, "type")
	}
	if expDrift {
		fields = append(fields, "expiration")
	}
	if maxDrift {
		fields = append(fields, "max_reads")
	}
	return fields
}
