// compliance_posture.go — a single, deployment-wide controls-posture snapshot for
// auditors (ISO 27001 / SOC 2 / NIS2 / DORA). GetCompliancePosture rolls up the
// state of the controls Keyorix already enforces — audit-trail integrity, access
// recertification coverage, dormant standing access, secret-rotation hygiene,
// second-factor coverage, and break-glass usage — into one structured object,
// grouped by control area. Read-only; gated by system.read.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// dormantThreshold is how long without a secret access marks a standing grant
// dormant in the posture roll-up.
const dormantThreshold = 90 * 24 * time.Hour

// AuditIntegrityPosture summarises the tamper-evident audit trail (ADR-029).
type AuditIntegrityPosture struct {
	ChainVerified bool   `json:"chain_verified"`
	ChainedEvents int64  `json:"chained_events"`
	Checkpointed  bool   `json:"checkpointed"`
	Reason        string `json:"reason,omitempty"` // failure/notes when not fully verified
}

// AccessGovernancePosture summarises access recertification + dormant access.
type AccessGovernancePosture struct {
	Projects                 int `json:"projects"`
	ProjectsWithOpenCampaign int `json:"projects_with_open_campaign"`
	ProjectsNeverReviewed    int `json:"projects_never_reviewed"`
	OpenCampaigns            int `json:"open_campaigns"`
	PendingItems             int `json:"pending_items"`       // undecided items across open campaigns
	DormantRoleGrants        int `json:"dormant_role_grants"` // user role grants with no/old secret access
	SoDViolations            int `json:"sod_violations"`      // principals holding a forbidden permission pair (A.5.3)
}

// RotationPosture summarises secret-rotation hygiene (ISO A.5.15 / NIS2).
type RotationPosture struct {
	CoveredSecrets int `json:"covered_secrets"`
	Overdue        int `json:"overdue"`
	DueSoon        int `json:"due_soon"`
}

// IdentityPosture summarises second-factor (MFA / passkey) coverage.
type IdentityPosture struct {
	ActiveUsers           int `json:"active_users"`
	UsersWithSecondFactor int `json:"users_with_second_factor"`
	SecondFactorPercent   int `json:"second_factor_percent"`
}

// EmergencyAccessPosture summarises break-glass usage (NIS2/DORA).
type EmergencyAccessPosture struct {
	ActiveActivations int `json:"active_activations"`
	TotalActivations  int `json:"total_activations"`
}

// LegalHoldPosture reports whether a litigation/investigation hold is in effect
// (ISO 27001 A.5.34) — while active the purge jobs preserve all records.
type LegalHoldPosture struct {
	Active   bool       `json:"active"`
	PlacedAt *time.Time `json:"placed_at,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

// AnomaliesPosture summarises detected access anomalies (NIS2 detection).
type AnomaliesPosture struct {
	Unacknowledged   int `json:"unacknowledged"`     // open alerts awaiting review
	HighSeverityOpen int `json:"high_severity_open"` // open alerts of high severity
}

// ClassificationPosture summarises secret data-classification coverage (A.5.12).
type ClassificationPosture struct {
	TotalSecrets int `json:"total_secrets"`
	Public       int `json:"public"`
	Internal     int `json:"internal"`
	Confidential int `json:"confidential"`
	Restricted   int `json:"restricted"`
	Unclassified int `json:"unclassified"`
}

// RetentionPosture reports the configured data-retention windows (ISO 27001 A.5.33
// / GDPR storage-limitation). Each value is a number of days; 0 means that record
// type is kept indefinitely. Enabled mirrors whether any window is set — evidence
// that storage-limitation is actively enforced rather than left unbounded.
type RetentionPosture struct {
	Enabled                    bool `json:"enabled"`
	AnomalyAlertsDays          int  `json:"anomaly_alerts_days"`
	ClosedAccessReviewsDays    int  `json:"closed_access_reviews_days"`
	BreakGlassDays             int  `json:"break_glass_days"`
	ResolvedAccessRequestsDays int  `json:"resolved_access_requests_days"`
}

// CompliancePosture is the deployment's control posture at a point in time.
type CompliancePosture struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	AuditIntegrity   AuditIntegrityPosture   `json:"audit_integrity"`
	AccessGovernance AccessGovernancePosture `json:"access_governance"`
	Rotation         RotationPosture         `json:"rotation"`
	Identity         IdentityPosture         `json:"identity"`
	EmergencyAccess  EmergencyAccessPosture  `json:"emergency_access"`
	Classification   ClassificationPosture   `json:"classification"`
	Anomalies        AnomaliesPosture        `json:"anomalies"`
	LegalHold        LegalHoldPosture        `json:"legal_hold"`
	Retention        RetentionPosture        `json:"retention"`
}

// GetCompliancePosture aggregates the deployment's control posture. It is an
// on-demand admin report (it walks every project for the access-governance roll-up),
// not a hot path.
func (c *KeyorixCore) GetCompliancePosture(ctx context.Context) (*CompliancePosture, error) {
	p := &CompliancePosture{GeneratedAt: c.now()}

	// Audit-trail integrity.
	if v, err := c.VerifyAuditChain(ctx); err == nil && v != nil {
		p.AuditIntegrity = AuditIntegrityPosture{
			ChainVerified: v.Valid,
			ChainedEvents: v.ChainedEvents,
			Checkpointed:  v.Checkpointed,
		}
		if !v.Valid {
			p.AuditIntegrity.Reason = v.Reason
		} else if v.CheckpointReason != "" {
			p.AuditIntegrity.Reason = v.CheckpointReason
		}
	} else if err != nil {
		p.AuditIntegrity.Reason = err.Error()
	}

	// Second-factor coverage across active users.
	if id, err := c.identityPosture(ctx); err == nil {
		p.Identity = id
	}

	// Rotation hygiene (deployment-wide).
	if statuses, err := c.GetRotationStatus(ctx, nil); err == nil {
		p.Rotation.CoveredSecrets = len(statuses)
		for _, s := range statuses {
			switch s.Status {
			case RotationStatusOverdue:
				p.Rotation.Overdue++
			case RotationStatusDueSoon:
				p.Rotation.DueSoon++
			}
		}
	}

	// Access governance + emergency access — per project.
	if err := c.accessGovernancePosture(ctx, p); err != nil {
		return nil, err
	}

	// Separation-of-duties violations (A.5.3).
	if violations, err := c.DetectSoDViolations(ctx); err == nil {
		p.AccessGovernance.SoDViolations = len(violations)
	}

	// Data-classification coverage (A.5.12).
	p.Classification = c.classificationPosture(ctx)

	// Open access anomalies (NIS2 detection).
	unack := false
	if alerts, err := c.storage.ListAnomalyAlerts(ctx, &unack); err == nil {
		p.Anomalies.Unacknowledged = len(alerts)
		for _, a := range alerts {
			if a.Severity == "high" {
				p.Anomalies.HighSeverityOpen++
			}
		}
	}

	// Legal hold (A.5.34).
	if hold, err := c.storage.GetActiveLegalHold(ctx); err == nil && hold != nil {
		at := hold.PlacedAt
		p.LegalHold = LegalHoldPosture{Active: true, PlacedAt: &at, Reason: hold.Reason}
	}

	// Data-retention windows (A.5.33).
	rp := c.retentionPolicy
	p.Retention = RetentionPosture{
		Enabled:                    rp.Configured(),
		AnomalyAlertsDays:          rp.AnomalyAlertsDays,
		ClosedAccessReviewsDays:    rp.ClosedAccessReviewsDays,
		BreakGlassDays:             rp.BreakGlassDays,
		ResolvedAccessRequestsDays: rp.ResolvedAccessRequestsDays,
	}
	return p, nil
}

// classificationPosture counts secrets per classification level via cheap count
// queries (PageSize 1 → only the total), rather than walking every secret row.
func (c *KeyorixCore) classificationPosture(ctx context.Context) ClassificationPosture {
	count := func(level string) int {
		f := &storage.SecretFilter{Page: 1, PageSize: 1}
		if level != "" {
			lvl := level
			f.Classification = &lvl
		}
		_, total, err := c.storage.ListSecrets(ctx, f)
		if err != nil {
			return 0
		}
		return int(total)
	}
	return ClassificationPosture{
		TotalSecrets: count(""),
		Public:       count(ClassificationPublic),
		Internal:     count(ClassificationInternal),
		Confidential: count(ClassificationConfidential),
		Restricted:   count(ClassificationRestricted),
		Unclassified: count("unclassified"),
	}
}

// identityPosture counts active users and how many have a second factor (MFA or
// passkey), paging through all of them (no silent cap).
func (c *KeyorixCore) identityPosture(ctx context.Context) (IdentityPosture, error) {
	const pageSize = 500
	var out IdentityPosture
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return out, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, u := range users {
			if !u.IsActive {
				continue
			}
			out.ActiveUsers++
			if u.MFAEnabled || u.WebAuthnEnabled {
				out.UsersWithSecondFactor++
			}
		}
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	if out.ActiveUsers > 0 {
		out.SecondFactorPercent = out.UsersWithSecondFactor * 100 / out.ActiveUsers
	}
	return out, nil
}

// accessGovernancePosture walks every project, rolling up campaign coverage,
// dormant role grants, and break-glass usage.
func (c *KeyorixCore) accessGovernancePosture(ctx context.Context, p *CompliancePosture) error {
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	p.AccessGovernance.Projects = len(projects)
	for _, proj := range projects {
		pid := proj.ID

		campaigns, err := c.ListAccessReviewCampaigns(ctx, pid)
		if err == nil {
			if len(campaigns) == 0 {
				p.AccessGovernance.ProjectsNeverReviewed++
			}
			hasOpen := false
			for _, cw := range campaigns {
				if cw.Campaign.State == CampaignStateOpen {
					hasOpen = true
					p.AccessGovernance.OpenCampaigns++
					p.AccessGovernance.PendingItems += cw.Progress.Pending
				}
			}
			if hasOpen {
				p.AccessGovernance.ProjectsWithOpenCampaign++
			}
		}

		p.AccessGovernance.DormantRoleGrants += c.countDormantRoleGrants(ctx, pid)

		if acts, err := c.ListBreakGlassActivations(ctx, pid); err == nil {
			p.EmergencyAccess.TotalActivations += len(acts)
			for _, a := range acts {
				if a.State == BreakGlassActive {
					p.EmergencyAccess.ActiveActivations++
				}
			}
		}
	}
	return nil
}

// countDormantRoleGrants counts distinct users holding a role grant in the project
// who have not accessed a secret recently (or ever) — stale standing access. Cheap:
// the project's role assignments + the last-activity map, no full secret walk.
func (c *KeyorixCore) countDormantRoleGrants(ctx context.Context, projectID uint) int {
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return 0
	}
	activity, err := c.storage.LastUserSecretActivity(ctx, projectID)
	if err != nil {
		return 0
	}
	cutoff := c.now().Add(-dormantThreshold)
	seen := map[uint]bool{}
	dormant := 0
	for _, a := range assignments {
		if a.PrincipalType != "user" || seen[a.PrincipalID] {
			continue
		}
		seen[a.PrincipalID] = true
		last, ok := activity[a.PrincipalID]
		if !ok || last.Before(cutoff) {
			dormant++
		}
	}
	return dormant
}
