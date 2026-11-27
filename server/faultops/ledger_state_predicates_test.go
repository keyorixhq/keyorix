package faultops

import (
	"encoding/json"
	"fmt"
	"slices"
)

// The acceptState predicates of opScopedBestEffortTable and
// effectThenErrorExclusion rows: each one states the documented end state of the
// tables its rows exempt, so a row accepts that shape and not any content of the
// table.

// changedRows returns the rows of table that are in after but not, byte for byte,
// in before (inserted or updated rows), decoded from their canonical JSON.
func changedRows(before, after dbSnapshot, table string) ([]map[string]any, error) {
	old := before.Tables[table].Rows
	var out []map[string]any
	for _, row := range after.Tables[table].Rows {
		if slices.Contains(old, row) {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(row), &fields); err != nil {
			return nil, fmt.Errorf("%s row %s: %w", table, row, err)
		}
		out = append(out, fields)
	}
	return out, nil
}

// issueLeaseAbortedState is the #4716 abort shape (abortUnauditedLease,
// internal/core/dynamic_secrets_issue_abort.go): IssueLease returned an error
// because its dynamic_lease.issued event was not recorded, so every lease row the
// request wrote is closed, `revoked` with reason `audit_unavailable`, or
// `revoke_failed` when the role could not be dropped (revokeOrRecordOrphan's
// orphan row is `revoke_failed` too). A row left `active` is a minted credential
// nobody received, with no issue audit event.
func issueLeaseAbortedState(before, after dbSnapshot) string {
	rows, err := changedRows(before, after, "DynamicSecretLease")
	if err != nil {
		return err.Error()
	}
	for _, r := range rows {
		switch r["Status"] {
		case "revoke_failed":
		case "revoked":
			if r["RevokeReason"] != "audit_unavailable" {
				return fmt.Sprintf("lease row revoked with reason %v, not audit_unavailable: %v", r["RevokeReason"], r)
			}
		default:
			return fmt.Sprintf("lease row left %v by a failed issue (want revoked/audit_unavailable or revoke_failed): %v", r["Status"], r)
		}
	}
	return ""
}

// accessReviewCampaignDegradedState is the ROLE-SHAPE-1 shape
// (flagEnvironmentWithoutProjectGrants, internal/core/env_without_project_grants.go):
// a failed grants lookup degrades the review, so every campaign row the request
// wrote carries Degraded with at least one reason.
func accessReviewCampaignDegradedState(before, after dbSnapshot) string {
	rows, err := changedRows(before, after, "AccessReviewCampaign")
	if err != nil {
		return err.Error()
	}
	for _, r := range rows {
		reasons, _ := r["DegradedReasons"].([]any)
		if r["Degraded"] != true || len(reasons) == 0 {
			return fmt.Sprintf("campaign row diverges without the degraded report (Degraded=%v, reasons=%v): %v",
				r["Degraded"], r["DegradedReasons"], r)
		}
	}
	return ""
}
