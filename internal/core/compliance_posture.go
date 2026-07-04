// compliance_posture.go — a single, deployment-wide controls-posture snapshot for
// auditors (ISO 27001 / SOC 2 / NIS2 / DORA). GetCompliancePosture rolls up the
// state of the controls Keyorix already enforces — audit-trail integrity, access
// recertification coverage, dormant standing access, secret-rotation hygiene,
// second-factor coverage, and break-glass usage — into one structured object,
// grouped by control area. Read-only; gated by audit.read (not the universal
// system_viewer baseline — see #255/#272 disclosure-family fix in router.go).
package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/trust"
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
	ProjectsOverdue          int `json:"projects_overdue"`    // overdue for recertification (A.5.18 cadence)
	DormantRoleGrants        int `json:"dormant_role_grants"` // per-grant: no/old activity at the capability tier the grant confers (#258)
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
// The flat fields count STATIC secrets (unchanged for back-compat); DynamicConfigs
// (and, later, machine entities) extend coverage to the other secret-bearing
// surfaces so the posture reflects classification across all of them.
type ClassificationPosture struct {
	TotalSecrets int `json:"total_secrets"`
	Public       int `json:"public"`
	Internal     int `json:"internal"`
	Confidential int `json:"confidential"`
	Restricted   int `json:"restricted"`
	Unclassified int `json:"unclassified"`
	// DynamicConfigs counts dynamic-secret configs by classification (A.5.12).
	DynamicConfigs ClassificationCounts `json:"dynamic_configs"`
	// MachineIdentities counts machine identities by classification (A.5.12).
	MachineIdentities ClassificationCounts `json:"machine_identities"`
	// MachineCredentials counts machine-token credentials by classification (A.5.12).
	MachineCredentials ClassificationCounts `json:"machine_credentials"`
}

// ClassificationCounts is a per-level tally of a set of classifiable entities.
type ClassificationCounts struct {
	Total        int `json:"total"`
	Public       int `json:"public"`
	Internal     int `json:"internal"`
	Confidential int `json:"confidential"`
	Restricted   int `json:"restricted"`
	Unclassified int `json:"unclassified"`
}

// classificationCountsFromMap builds ClassificationCounts from a label→count map
// (the empty label "" is the unclassified bucket).
func classificationCountsFromMap(m map[string]int) ClassificationCounts {
	cc := ClassificationCounts{
		Public:       m[ClassificationPublic],
		Internal:     m[ClassificationInternal],
		Confidential: m[ClassificationConfidential],
		Restricted:   m[ClassificationRestricted],
		Unclassified: m[""],
	}
	for _, n := range m {
		cc.Total += n
	}
	return cc
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

// RiskPosture summarises the risk register (ISO 27001 A.5.8 risk treatment): how
// many governed, time-bound exceptions are currently active and how many expire soon
// (so an auditor sees accepted-with-a-deadline risks rather than ungoverned gaps).
type RiskPosture struct {
	ActiveExceptions int `json:"active_exceptions"`
	ExpiringSoon     int `json:"expiring_soon"` // active exceptions expiring within the soon window
}

// CertificatePosture reports certificate hygiene from the cached cert expiry (ADR-056).
// NotEvaluated counts certificate-typed secrets whose certificate hasn't been parsed
// yet (no inspection/scan) — full coverage needs the certificate-expiry scan enabled.
type CertificatePosture struct {
	TotalCertificates int `json:"total_certificates"`
	Expired           int `json:"expired"`
	ExpiringSoon      int `json:"expiring_soon"` // within the 30-day window
	NotEvaluated      int `json:"not_evaluated"`
}

// CompliancePosture is the deployment's control posture at a point in time.
//
// #136: every sub-rollup is queried best-effort so one failing signal doesn't abort
// the whole snapshot — but a query failure must never read the same as "checked,
// found clean" (e.g. LegalHold.Active=false on a DB error looks identical to no hold
// in effect, and this snapshot gets HMAC-signed into evidence packs an auditor
// trusts). Degraded + DegradedReasons make a partial snapshot detectable instead of
// indistinguishable from a fully-clean one.
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
	Risk             RiskPosture             `json:"risk"`
	Certificates     CertificatePosture      `json:"certificates"`
	SupplyChain      SupplyChainPosture      `json:"supply_chain"`
	// Degraded is true when one or more sub-rollups below could not be queried — the
	// zero/clean values they carry are UNKNOWN, not verified-clean. An evidence pack
	// consumer must treat a degraded snapshot as incomplete, not passing.
	Degraded bool `json:"degraded"`
	// DegradedReasons names each failed sub-rollup with its underlying error.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
}

// degrade records that a posture sub-rollup could not be queried: it flips Degraded
// and appends a human-readable reason, so evidence packs signal "incomplete" instead
// of silently reading the affected fields as a verified-clean zero value.
func (p *CompliancePosture) degrade(area string, err error) {
	p.Degraded = true
	p.DegradedReasons = append(p.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// DegradedArea reports whether any recorded DegradedReasons entry names an area
// starting with one of the given prefixes — i.e. whether the specific signal a
// consumer (e.g. the control-framework matrix) depends on failed to collect this
// run. Used so a downstream "pass/gap" evaluation derived from a degraded field
// can surface as unknown rather than silently trusting the field's zero value.
func (p *CompliancePosture) DegradedArea(prefixes ...string) bool {
	for _, reason := range p.DegradedReasons {
		for _, prefix := range prefixes {
			if strings.HasPrefix(reason, prefix) {
				return true
			}
		}
	}
	return false
}

// SupplyChainPosture reports software-supply-chain integrity: whether this deployment
// verifies updates against a pinned signing key (ADR-062/064) and the offline-entitlement
// state (ADR-065). A signed-release deployment embeds the update-signing key, so every
// update bundle is verified offline against it before it can be staged.
type SupplyChainPosture struct {
	// UpdateSigningTrusted is true when at least one update-signing key is pinned into this
	// build — i.e. update bundles are verified against a trusted key (a signed release).
	UpdateSigningTrusted bool `json:"update_signing_trusted"`
	// TrustedUpdateKeys is how many update-signing key-ids are pinned (≥1 in a release).
	TrustedUpdateKeys int `json:"trusted_update_keys"`
	// LicenseState is the offline-license state ("active"/"expiring_soon"/.../"none").
	LicenseState string `json:"license_state"`
	// LicenseValid is true when the license currently grants commercial features.
	LicenseValid bool `json:"license_valid"`
}

// riskExpiringSoonWindow is how far ahead an active exception counts as "expiring
// soon" in the posture.
const riskExpiringSoonWindow = 14 * 24 * time.Hour

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
		p.degrade("audit_integrity", err)
	}

	// Second-factor coverage across active users.
	if id, err := c.identityPosture(ctx); err == nil {
		p.Identity = id
	} else {
		p.degrade("identity", err)
	}

	// Rotation hygiene (deployment-wide).
	if statuses, err := c.GetRotationStatus(ctx, nil, nil); err == nil {
		p.Rotation.CoveredSecrets = len(statuses)
		for _, s := range statuses {
			switch s.Status {
			case RotationStatusOverdue:
				p.Rotation.Overdue++
			case RotationStatusDueSoon:
				p.Rotation.DueSoon++
			}
		}
	} else {
		p.degrade("rotation", err)
	}

	// Access governance + emergency access — per project.
	if err := c.accessGovernancePosture(ctx, p); err != nil {
		return nil, err
	}

	// Separation-of-duties violations (A.5.3), net of governed risk exceptions
	// (#170): an approved, active "sod"-category exception suppresses only the ONE
	// violation it names, not the whole SoD control.
	if sod, err := c.DetectSoDViolations(ctx); err == nil {
		p.AccessGovernance.SoDViolations = len(c.suppressExceptedSoDViolations(ctx, sod.Violations))
		// #420: a principal whose permissions couldn't be read means the scan may be
		// missing a violation for them — the posture rollup must say so too, not just
		// count what it managed to see.
		for _, reason := range sod.DegradedReasons {
			p.degrade("sod_violations", fmt.Errorf("%s", reason))
		}
	} else {
		p.degrade("sod_violations", err)
	}

	// Data-classification coverage (A.5.12).
	p.Classification = c.classificationPosture(ctx, p)

	// Open access anomalies (NIS2 detection).
	unack := false
	if alerts, err := c.storage.ListAnomalyAlerts(ctx, &unack); err == nil {
		p.Anomalies.Unacknowledged = len(alerts)
		for _, a := range alerts {
			if a.Severity == "high" {
				p.Anomalies.HighSeverityOpen++
			}
		}
	} else {
		p.degrade("anomalies", err)
	}

	// Legal hold (A.5.34).
	if hold, err := c.storage.GetActiveLegalHold(ctx); err == nil {
		if hold != nil {
			at := hold.PlacedAt
			p.LegalHold = LegalHoldPosture{Active: true, PlacedAt: &at, Reason: hold.Reason}
		}
	} else {
		p.degrade("legal_hold", err)
	}

	// Risk register — governed, time-bound exceptions (A.5.8).
	if active, soon, err := c.CountActiveRiskExceptions(ctx, riskExpiringSoonWindow); err == nil {
		p.Risk = RiskPosture{ActiveExceptions: active, ExpiringSoon: soon}
	} else {
		p.degrade("risk", err)
	}

	// Certificate hygiene from the cached cert expiry (ADR-056).
	p.Certificates = c.certificatePosture(ctx, p)

	// Data-retention windows (A.5.33).
	rp := c.retentionPolicy
	p.Retention = RetentionPosture{
		Enabled:                    rp.Configured(),
		AnomalyAlertsDays:          rp.AnomalyAlertsDays,
		ClosedAccessReviewsDays:    rp.ClosedAccessReviewsDays,
		BreakGlassDays:             rp.BreakGlassDays,
		ResolvedAccessRequestsDays: rp.ResolvedAccessRequestsDays,
	}

	// Supply-chain integrity (ADR-062/064/065): signed, offline-verifiable updates plus
	// offline entitlement. A non-release/source build pins no keys (control not in force).
	sc := SupplyChainPosture{}
	if reg, rerr := c.defaultTrustRegistry(); rerr == nil && reg != nil {
		ids := reg.KeyIDs(trust.PurposeUpdate)
		sc.TrustedUpdateKeys = len(ids)
		sc.UpdateSigningTrusted = len(ids) > 0
	} else if rerr != nil {
		// DefaultRegistry only errors when the embedded key material itself is
		// malformed (a build/release integrity problem) — distinct from an
		// ordinary unsigned/source build, which parses its empty key spec with a
		// nil error. Left un-degraded, this read the same as "no keys embedded"
		// (NotConfigured), masking a genuine "couldn't even check" failure.
		p.degrade("supply_chain", rerr)
	}
	ls := c.LicenseStatus()
	sc.LicenseState = string(ls.State)
	sc.LicenseValid = ls.Grants()
	p.SupplyChain = sc

	return p, nil
}

// suppressExceptedSoDViolations drops any violation covered by an active, APPROVED
// "sod"-category risk exception whose Reference matches it exactly (#170). Before
// this, a registered exception was purely decorative — GetCompliancePosture
// reported every raw violation regardless, so the "governed acceptance" mechanism
// didn't actually accept anything. Fails safe: a lookup error reports every
// violation unfiltered rather than risking an under-count from a partial exception
// list.
func (c *KeyorixCore) suppressExceptedSoDViolations(ctx context.Context, violations []SoDViolation) []SoDViolation {
	if len(violations) == 0 {
		return violations
	}
	exceptions, err := c.ListRiskExceptions(ctx, true) // active only (not revoked, not expired)
	if err != nil {
		return violations
	}
	excepted := make(map[string]bool, len(exceptions))
	for _, e := range exceptions {
		if e.Category != "sod" || !e.Approved {
			continue
		}
		excepted[e.Reference] = true
	}
	if len(excepted) == 0 {
		return violations
	}
	out := make([]SoDViolation, 0, len(violations))
	for _, v := range violations {
		if excepted[v.Reference] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// classificationPosture counts secrets per classification level via cheap count
// queries (PageSize 1 → only the total), rather than walking every secret row.
// Reports into cp.degrade on any failed count so a query error reads as "unknown",
// not as a verified-zero count for that classification/entity kind.
func (c *KeyorixCore) classificationPosture(ctx context.Context, cp *CompliancePosture) ClassificationPosture {
	count := func(level string) int {
		f := &storage.SecretFilter{Page: 1, PageSize: 1}
		if level != "" {
			lvl := level
			f.Classification = &lvl
		}
		_, total, err := c.storage.ListSecrets(ctx, f)
		if err != nil {
			cp.degrade("classification:secrets:"+level, err)
			return 0
		}
		return int(total)
	}
	p := ClassificationPosture{
		TotalSecrets: count(""),
		Public:       count(ClassificationPublic),
		Internal:     count(ClassificationInternal),
		Confidential: count(ClassificationConfidential),
		Restricted:   count(ClassificationRestricted),
		Unclassified: count("unclassified"),
	}
	if m, err := c.storage.CountDynamicSecretConfigsByClassification(ctx); err == nil {
		p.DynamicConfigs = classificationCountsFromMap(m)
	} else {
		cp.degrade("classification:dynamic_configs", err)
	}
	if m, err := c.storage.CountMachineIdentitiesByClassification(ctx); err == nil {
		p.MachineIdentities = classificationCountsFromMap(m)
	} else {
		cp.degrade("classification:machine_identities", err)
	}
	if m, err := c.storage.CountMachineIdentityCredentialsByClassification(ctx); err == nil {
		p.MachineCredentials = classificationCountsFromMap(m)
	} else {
		cp.degrade("classification:machine_credentials", err)
	}
	return p
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
	recertCutoff := c.now().AddDate(0, 0, -c.recertCadence())
	for _, proj := range projects {
		pid := proj.ID

		campaigns, err := c.ListAccessReviewCampaigns(ctx, pid)
		if err == nil {
			if len(campaigns) == 0 {
				p.AccessGovernance.ProjectsNeverReviewed++
			}
			open, lastClosed := splitCampaigns(campaigns)
			if open != nil {
				p.AccessGovernance.ProjectsWithOpenCampaign++
				p.AccessGovernance.OpenCampaigns++
				p.AccessGovernance.PendingItems += open.Progress.Pending
			} else {
				// No review in progress — overdue if never reviewed, or the last
				// campaign closed longer ago than the recertification cadence (A.5.18).
				overdue := lastClosed == nil
				if lastClosed != nil && lastClosed.Campaign.ClosedAt != nil {
					overdue = lastClosed.Campaign.ClosedAt.Before(recertCutoff)
				}
				if overdue {
					p.AccessGovernance.ProjectsOverdue++
				}
			}
		} else {
			p.degrade(fmt.Sprintf("access_governance:campaigns:project=%d", pid), err)
		}

		p.AccessGovernance.DormantRoleGrants += c.countDormantRoleGrants(ctx, pid, p)

		if acts, err := c.ListBreakGlassActivations(ctx, pid); err == nil {
			p.EmergencyAccess.TotalActivations += len(acts)
			for _, a := range acts {
				if a.State == BreakGlassActive {
					p.EmergencyAccess.ActiveActivations++
				}
			}
		} else {
			p.degrade(fmt.Sprintf("emergency_access:project=%d", pid), err)
		}
	}
	return nil
}

// countDormantRoleGrants counts individual role grants in the project that are
// stale standing access — a grant whose holder hasn't exercised the CAPABILITY it
// confers recently (or ever). Cheap: the project's role assignments + the two
// last-activity maps, no full secret walk.
//
// Per-grant, not per-user (#258): a user can hold several role grants in the same
// project — e.g. an everyday project_viewer grant they use weekly, plus a
// project_admin grant handed out "just in case" that they've never actually
// exercised. Counting dormancy per USER (as this used to) meant that ordinary
// secret-read activity under the viewer grant masked the separate, genuinely-stale
// admin grant as "non-dormant" — the coarse per-project activity check couldn't
// tell which grant the activity was attributable to. Each (principal, role) grant
// is now assessed independently, so the unused admin-tier grant is correctly
// flagged even though the same user is actively reading secrets elsewhere.
//
// The activity signal used per grant depends on the role's tier (roleIsAdminTier):
//   - A plain read/write-tier role is "used" by ANY entry in LastUserSecretActivity
//     (a secret read is exactly what such a role exists to enable).
//   - An admin-tier role (secrets.delete/admin, or a role-management permission
//     like roles.assign) additionally requires an entry in
//     LastUserElevatedActivity — an actually-observed elevated action — since
//     ordinary secret reads don't attest to the ADMIN capability being used at all.
//
// This is an approximation, not a perfect per-grant attribution: the audit trail
// doesn't record which specific grant authorized a given action, only that SOME
// elevated action occurred. A user holding two admin-tier grants in the project
// who exercises either one will show both as "used". See roleIsAdminTier's doc for
// the exact boundary and its limits.
func (c *KeyorixCore) countDormantRoleGrants(ctx context.Context, projectID uint, cp *CompliancePosture) int {
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:assignments:project=%d", projectID), err)
		return 0
	}
	activity, err := c.storage.LastUserSecretActivity(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:activity:project=%d", projectID), err)
		return 0
	}
	elevated, err := c.storage.LastUserElevatedActivity(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:elevated_activity:project=%d", projectID), err)
		return 0
	}
	cutoff := c.now().Add(-dormantThreshold)

	adminTierByRole := map[uint]bool{}
	degradedRoles := map[uint]bool{}
	isAdminTier := func(roleID uint) bool {
		if v, ok := adminTierByRole[roleID]; ok {
			return v
		}
		perms, err := c.storage.GetRolePermissions(ctx, roleID)
		if err != nil {
			// Can't classify this role's tier; degrade once per role and fall back to
			// the plain read/write activity check rather than silently under- or
			// over-counting.
			if !degradedRoles[roleID] {
				degradedRoles[roleID] = true
				cp.degrade(fmt.Sprintf("dormant_role_grants:role_permissions:project=%d:role=%d", projectID, roleID), err)
			}
			adminTierByRole[roleID] = false
			return false
		}
		v := roleIsAdminTier(perms)
		adminTierByRole[roleID] = v
		return v
	}

	seen := map[[2]uint]bool{} // dedup identical (principal, role) grant rows
	dormant := 0
	for _, a := range assignments {
		if a.PrincipalType != "user" {
			continue
		}
		key := [2]uint{a.PrincipalID, a.RoleID}
		if seen[key] {
			continue
		}
		seen[key] = true

		if isAdminTier(a.RoleID) {
			last, ok := elevated[a.PrincipalID]
			if !ok || last.Before(cutoff) {
				dormant++
			}
			continue
		}
		last, ok := activity[a.PrincipalID]
		if !ok || last.Before(cutoff) {
			dormant++
		}
	}
	return dormant
}
