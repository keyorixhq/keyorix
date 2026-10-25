package storage

// Storage defines the unified interface for data persistence operations.
// LocalStorage (internal/storage/store) is the sole implementation today.
// A second implementation, RemoteStorage, proxied every call over HTTP to an
// upstream server; it has since been deleted (ADR-083/ADR-108: remote storage
// is a CLI/client-mode concept, not a server storage backend). Several method
// pairs below (e.g. TryAcquireSchedulerLock/ReleaseSchedulerLock instead of a
// single WithSchedulerLock-only API) still carry doc comments explaining the
// cross-process-atomicity constraints RemoteStorage's HTTP-proxy nature used
// to impose — kept as design history for why the interface has the shape it
// does, not because a second implementation still exists.
type Storage interface {
	LockingStore
	ProjectStore
	MembershipStore
	UserStore
	GroupStore
	RBACStore
	ConnectorStore
	SessionStore
	MFAStore
	WebAuthnStore
	PATStore
	SetupTokenStore
	MachineStore
	SecretStore
	SharingStore
	AccessStore
	ComplianceStore
	AuditStore
	AnomalyStore
	NotificationStore
	DynamicStore
	RotationStore
	TemplateStore
	RetentionStore
	SystemStore
}
