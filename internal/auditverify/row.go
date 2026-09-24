package auditverify

import "time"

// AuditEventRow is this package's own, independent representation of an
// audit_events row — deliberately not internal/storage/models.AuditEvent
// (see doc.go). Field types mirror the wire/storage shape closely enough
// that DecodeAuditEventRow can be driven directly off a database/sql Scan,
// but nothing here imports the server's model package.
type AuditEventRow struct {
	ID             uint64
	EventType      string
	UserID         *uint64
	SecretNodeID   *uint64
	ProjectID      *uint64
	IPAddress      string
	Description    string
	Success        *bool
	EventTime      time.Time
	Diff           string
	ImpersonatedBy *uint64
	ActingAs       *uint64
	Impersonation  bool
	ActorType      string
	PrevHash       string
	EntryHash      string
}
