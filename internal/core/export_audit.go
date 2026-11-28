package core

// export_audit.go — bulk exports of security-relevant data are audited BEFORE the
// export is delivered, fail-closed (AUDIT-FAILCLOSED-SECRETS-1, #4721), the
// audit-before-disclosure rule the secret-value reads and the crypto inventory
// (crypto_inventory_audit.go) follow. None of these exports carries a secret value,
// and no row written here carries export content: counts, format, filters and
// targets only.
//
// Not audited, on purpose: the JSON SIEM pull feed GET /api/v1/audit/export. A
// collector polls it by cursor, so a row per poll would be returned by the next
// poll and the feed would never be caught up (one row per poll, forever). Pinned by
// server/http TestAuditExportFeed_WritesNoAuditRowOfItsOwn; ADR-112 notes it.

import (
	"context"
	"fmt"
)

const (
	// EventComplianceEvidenceExported: a compliance evidence pack is about to be
	// delivered (REST download or the scheduled export).
	EventComplianceEvidenceExported = "compliance.evidence_exported"
	// EventComplianceEvidenceDeliveryFailed: the scheduled export's off-box delivery
	// failed after its exported row was written (the pack still went to the file
	// target, if any).
	EventComplianceEvidenceDeliveryFailed = "compliance.evidence_delivery_failed"
	// EventAuditLogExported: a CSV download of the audit log is about to start.
	EventAuditLogExported = "audit.exported"
	// EventSecretAccessLogExported: one secret's access history is about to be
	// returned as a file.
	EventSecretAccessLogExported = "secret.access_log_exported"
)

// ExportAuditUnavailableMessage is the fixed client text of an export refused
// because its audit row could not be recorded.
const ExportAuditUnavailableMessage = "could not record the export in the audit log; nothing was exported, retry"

// logExportBeforeDelivery writes an export's row and reports whether it landed. An
// unrecorded row is ErrMutationAuditUnavailable (wrapped): the caller must deliver
// nothing.
func (c *KeyorixCore) logExportBeforeDelivery(ctx context.Context, eventType string, actorID, secretID, projectID *uint, ip, description string) error {
	if !c.writeAuditEventFull(ctx, eventType, actorID, secretID, projectID, ip, description) {
		return fmt.Errorf("%w: audit event %q was not recorded", ErrMutationAuditUnavailable, eventType)
	}
	return nil
}

// LogComplianceEvidenceExported records a REST download of the evidence pack
// before it is sent. actorID is the caller (0 = none).
func (c *KeyorixCore) LogComplianceEvidenceExported(ctx context.Context, actorID uint, ip, filename string, size int, signed bool) error {
	return c.logExportBeforeDelivery(ctx, EventComplianceEvidenceExported, actorPtr(actorID), nil, nil, ip,
		fmt.Sprintf("compliance evidence pack %q downloaded (%d bytes, signed=%t)", filename, size, signed))
}

// LogAuditLogExported records a CSV export of the audit log before its first byte
// is sent. filter describes the requested rows (limit, project, user, time window).
func (c *KeyorixCore) LogAuditLogExported(ctx context.Context, actorID uint, ip, format, filter string) error {
	return c.logExportBeforeDelivery(ctx, EventAuditLogExported, actorPtr(actorID), nil, nil, ip,
		fmt.Sprintf("audit log exported as %s (%s)", format, filter))
}
