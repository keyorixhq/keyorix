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

	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"gorm.io/gorm"
)

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
}

// NewLocalStorage creates a LocalStorage backed by the given *gorm.DB.
func NewLocalStorage(db *gorm.DB) *LocalStorage {
	return &LocalStorage{db: db}
}
