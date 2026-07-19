// Package store handles secret persistence across remote and local backends.
//
// # Domain
//
// Two storage backends implement the core [storage.Storage] interface:
//
//   - RemoteStorage — proxies all operations to a running Keyorix server via
//     the REST API. Used by the CLI when a server is reachable.
//   - LocalStorage  — accesses the database directly via GORM. Used by the
//     server itself and for air-gapped / offline deployments.
//
// # Operation Map
//
// Navigate directly to the file for the operation you need:
//
//	Secrets (node + version):
//	  remote_secrets.go  /  local_secrets.go
//
//	Sharing (ShareRecord):
//	  remote_sharing.go  /  local_sharing.go   (local: not yet implemented)
//
//	Users & Groups:
//	  remote_users.go    /  local_users.go
//
//	Roles & RBAC:
//	  remote_rbac.go     /  local_rbac.go
//
//	Audit & Anomaly:
//	  remote_audit.go    /  local_audit.go
//
//	Sessions & API Clients:
//	  remote_auth.go     /  local_auth.go
//
//	Stats & Health:
//	  remote_stats.go    /  local_stats.go
//
// # Struct Constructors
//
//	NewRemoteStorage(config *remote.Config) (*RemoteStorage, error)
//	NewLocalStorage(db *gorm.DB) *LocalStorage
//
// Both constructors live in this file. Configuration and HTTP transport for
// RemoteStorage are in the sibling remote/ package (config.go, client.go).
//
// # Entry Point
//
// Start here. Read this comment, then open the single operation file you need.
// You do NOT need to read all files — each file is self-contained.
package store

import (
	"fmt"
	"sync"

	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"gorm.io/gorm"
)

// maxStoragePageSize is a defense-in-depth ceiling applied directly inside
// LocalStorage's paginated queries (secrets, users, audit events), on top of
// whatever clamp (if any) the caller already applied. External HTTP/gRPC
// handlers already clamp page_size to <=100 before it reaches storage, but
// several trusted internal callers intentionally request larger single-shot
// pages (e.g. secretInventoryMaxRows/csvExportMaxRows = 10000, ListSecrets
// with OwnerID PageSize 10000). 10000 is chosen to sit above every current
// legitimate call site in the repo — this clamp is a true no-op for existing
// behavior today, and only guards a FUTURE caller that forgets to clamp
// (or passes a hostile/overflowed value) from forcing an unbounded SQL LIMIT.
const maxStoragePageSize = 10000

// clampPageSize bounds a caller-supplied page size to (0, maxStoragePageSize].
// A non-positive size is passed through unchanged — several callers rely on
// their own default/zero-value handling before this clamp runs.
func clampPageSize(pageSize int) int {
	if pageSize > maxStoragePageSize {
		return maxStoragePageSize
	}
	return pageSize
}

// RemoteStorage implements storage.Storage via the Keyorix REST API.
type RemoteStorage struct {
	client *remote.HTTPClient
}

// NewRemoteStorage creates a RemoteStorage backed by the given config.
func NewRemoteStorage(config *remote.Config) (*RemoteStorage, error) {
	client, err := remote.NewHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	return &RemoteStorage{client: client}, nil
}

// LocalStorage implements storage.Storage via direct GORM database access.
type LocalStorage struct {
	db *gorm.DB
	// auditChainMu serializes audit-event appends so the read-chain-head +
	// insert critical section is atomic within this process (ADR-029). The
	// PostgreSQL advisory lock in LogAuditEvent extends this across processes.
	// A pointer so a transaction-scoped LocalStorage (see WithTransaction) shares the
	// SAME mutex as its parent — otherwise an audit append inside a transaction would
	// not serialize against concurrent appends on the base store.
	auditChainMu *sync.Mutex
	// auditCheckpointMu serializes WriteAuditCheckpoint's chain-walk + decide +
	// create-checkpoint sequence within this process (ADR-029/#300). The PostgreSQL
	// advisory lock in WithAuditCheckpointLock extends this across processes/replicas
	// (ADR-039 HA). A pointer for the same reason as auditChainMu — a transaction-scoped
	// LocalStorage must share its parent's mutex.
	auditCheckpointMu *sync.Mutex
}

// NewLocalStorage creates a LocalStorage backed by the given *gorm.DB.
func NewLocalStorage(db *gorm.DB) *LocalStorage {
	return &LocalStorage{db: db, auditChainMu: &sync.Mutex{}, auditCheckpointMu: &sync.Mutex{}}
}

// DB returns the underlying *gorm.DB. Exposed for test helpers that need direct
// SQL access (e.g. seeding rows with custom timestamps). Do not use in production
// code — all writes must go through the Storage interface methods.
func (ls *LocalStorage) DB() *gorm.DB {
	return ls.db
}
