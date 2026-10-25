package storage

// AuditFilter defines filtering options for audit log queries
// NotificationScope selects the notifications that carry a project: every such row
// when ProjectID is 0, otherwise only that project's. A notification with no project
// is never in any scope.
type NotificationScope struct {
	ProjectID uint
}
