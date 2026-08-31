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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

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
// A non-positive size is passed through as 0 rather than negative — several
// callers rely on 0 meaning "use my own default" before this clamp runs, but
// a negative value must never reach GORM's Limit(): Limit(-1) (or any
// negative) removes the LIMIT clause entirely, turning a caller-controlled
// negative page size into an unbounded query (#G44).
func clampPageSize(pageSize int) int {
	if pageSize > maxStoragePageSize {
		return maxStoragePageSize
	}
	if pageSize < 0 {
		return 0
	}
	return pageSize
}

// maxStoragePage is the maximum page number accepted by paginated queries.
// Without a ceiling, a hostile caller can force OFFSET = (page-1)*pageSize
// into the millions, which SQLite/Postgres must scan and discard before
// returning any rows — a cheap denial-of-service against the audit endpoint.
// 10000 pages × up to 100 rows/page = 1 million rows, far above any real
// audit log a single deployment would accumulate.
const maxStoragePage = 10_000

// maxUnboundedListRows caps LocalStorage list queries that have no caller-
// supplied pagination at all (no Page/PageSize/limit param in their
// signature) — a defense-in-depth ceiling so a table that grows without
// bound in production (rotation policies, SoD policies, dynamic leases,
// access-review campaigns, etc.) can't turn a routine list call into an
// unbounded full-table scan (#G44).
const maxUnboundedListRows = 10000

// clampPage bounds a caller-supplied page number to [1, maxStoragePage].
func clampPage(page int) int {
	if page < 1 {
		return 1
	}
	if page > maxStoragePage {
		return maxStoragePage
	}
	return page
}

// escapeLIKE escapes SQL LIKE wildcard metacharacters (%, _) in a caller-supplied
// string using backslash as the escape character. Callers must also append
// ESCAPE '\' to the LIKE clause so the database honours the escapes.
// Without this, a search for "foo%bar" would match any string starting with
// "foo" rather than the literal token, turning a user-controlled LIKE operand
// into a wildcard injection vector.
func escapeLIKE(s string) string {
	// Replace \ first to avoid double-escaping already-present backslashes.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
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

// putConditionalTransition PUTs body to path and decodes the standard
// {"matched": bool} response shared by every conditional-transition storage
// primitive in this package (TransitionMachineIdentityState,
// TransitionSecretStatus, TransitionDynamicSecretConfigDisabled,
// UpdateUserIfActiveStateMatches, ...): each one carries a full row plus the
// "from" value the caller observed before mutating it, so the upstream can
// apply the exact same conditional "WHERE id = ? AND <field> = ?" write its
// own LocalStorage would in a single round trip (see the atomicity note in
// internal/core/storage/interface.go for why a generic read-then-write proxy
// pair isn't safe here: RemoteStorage.WithTransaction is a no-op passthrough).
//
// opName is used only to build each call site's own wrapped error text
// ("failed to %s: %w" / "%s failed: %s"), so callers keep their existing
// exact error messages.
func (rs *RemoteStorage) putConditionalTransition(ctx context.Context, path string, body interface{}, opName string) (bool, error) {
	resp, err := rs.client.Put(ctx, path, body)
	if err != nil {
		return false, fmt.Errorf("failed to %s: %w", opName, err)
	}
	if !resp.Success {
		return false, fmt.Errorf("%s failed: %s", opName, resp.Error.Error())
	}
	var result struct {
		Matched bool `json:"matched"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Matched, nil
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
	// bootstrapMu serializes BootstrapSystem's whole check-then-create sequence
	// within this process (#339/ADR-039 HA). The PostgreSQL advisory lock in
	// WithBootstrapLock extends this across processes/replicas. A pointer for the
	// same reason as auditChainMu/auditCheckpointMu — a transaction-scoped
	// LocalStorage must share its parent's mutex.
	bootstrapMu *sync.Mutex
	// namedLockMu is the in-process fallback for WithNamedLock (#1646) on a
	// non-Postgres backend (SQLite, single-process by construction): a single
	// shared mutex, not sharded per lock key, mirroring auditCheckpointMu/
	// bootstrapMu's own single-mutex shape. On PostgreSQL, WithNamedLock instead
	// takes a session advisory lock keyed by lockKey's hash, extending the
	// serialization across replicas (ADR-039 HA) -- this mutex is skipped
	// entirely on that path. A pointer for the same sharing reason as every
	// other mutex on this struct.
	namedLockMu *sync.Mutex
	// consumeClockWatermark backs consumeClockLooksRegressed (#1632): an
	// in-memory monotonic high-water mark of the latest wall-clock instant a
	// single-use-token consumption (ConsumeMFAChallenge, ConsumeWebAuthnSession)
	// has legitimately observed, in this process's lifetime. A pointer for the
	// same reason as the mutexes above — ConsumeMFAChallenge and
	// ConsumeWebAuthnSession are two distinct call paths (one via the core
	// layer's c.now(), one via a raw storage call from an HTTP handler; see
	// consumeClockLooksRegressed's doc comment) that must share ONE
	// watermark, not warm two independent ones.
	consumeClockWatermark *clockWatermark
	// rbacClockWatermark backs rbacEffectiveNow (#1632): an in-memory monotonic
	// high-water mark of the latest wall-clock instant any RBAC permission-
	// resolution query in local_rbac.go has legitimately observed. Unlike
	// consumeClockWatermark (which backs a REFUSAL of a single, discrete
	// action), this backs a CLAMP applied to a pervasive, high-volume read
	// path reached on every authorized request — see rbacEffectiveNow's doc
	// comment for why the two sites need different response shapes to the
	// same underlying fact. A pointer for the same sharing reason as every
	// other watermark/mutex field on this struct.
	rbacClockWatermark *clockWatermark
}

// clockWatermark pairs a mutex with the time.Time it guards, so a single
// pointer field on LocalStorage can be shared across transaction-scoped
// copies (see WithTransaction) without copying the mutex and the time value
// out of sync with each other.
type clockWatermark struct {
	mu   sync.Mutex
	time time.Time
}

// NewLocalStorage creates a LocalStorage backed by the given *gorm.DB.
func NewLocalStorage(db *gorm.DB) *LocalStorage {
	return &LocalStorage{
		db:                    db,
		auditChainMu:          &sync.Mutex{},
		auditCheckpointMu:     &sync.Mutex{},
		bootstrapMu:           &sync.Mutex{},
		namedLockMu:           &sync.Mutex{},
		consumeClockWatermark: &clockWatermark{},
		rbacClockWatermark:    &clockWatermark{},
	}
}

// DB returns the underlying *gorm.DB. Exposed for test helpers that need direct
// SQL access (e.g. seeding rows with custom timestamps). Do not use in production
// code — all writes must go through the Storage interface methods.
func (ls *LocalStorage) DB() *gorm.DB {
	return ls.db
}

// consumeClockRegressionTolerance bounds how far now may read EARLIER than
// consumeClockWatermark before checkConsumeClockNotRegressed refuses a
// single-use-token consumption. Mirrors internal/core's
// secretExpiryClockRegressionTolerance (#1632) -- same threat model (an
// operator, or an NTP-less clock correction, stepping the host clock back by
// an hour or more), same tolerance for ordinary NTP slew.
const consumeClockRegressionTolerance = 30 * time.Second

// consumeClockLooksRegressed reports whether now looks EARLIER than a time
// this process has already legitimately observed for a single-use-token
// consumption (ConsumeMFAChallenge, ConsumeWebAuthnSession) (#1632). Both
// consumption methods bind now directly into a SQL `expires_at > ?` bound,
// with no caching layer between the wall clock and the comparison -- a host
// clock stepped backward past a challenge/session's real expiry would let it
// be consumed for the first time past its real window (this cannot enable
// replay of an ALREADY-consumed row: the `used_at IS NULL` predicate is
// clock-independent).
//
// Returns a bool rather than an error so each caller can return its OWN
// existing "invalid or expired X" text on a regression, matching the exact
// wording its normal expiry path already uses -- a caller must not be able
// to distinguish "genuinely expired" from "clock regression detected" by
// the error text differing between the two refusal reasons.
//
// This watermark is shared by both methods rather than kept per-method,
// because they have two genuinely distinct callers each (one via the core
// layer's c.now(), one via a raw storage call from an HTTP handler that
// passes a bare time.Now() -- see users_crud.go's ConsumeMFAChallenge and
// webauthn_proxy.go's ConsumeWebAuthnSessionProxy) and the fact being
// defended against -- "has this process's OS clock been stepped backward" --
// is a single process-wide fact, not a per-method one.
//
// On a non-regressed reading, advances the watermark to now (never
// backward, for the same reason as internal/core's
// checkSecretExpiryClockNotRegressed: a second, slower backward step must
// not walk the watermark down unnoticed).
func (ls *LocalStorage) consumeClockLooksRegressed(now time.Time) bool {
	wm := ls.consumeClockWatermark
	wm.mu.Lock()
	defer wm.mu.Unlock()
	if !wm.time.IsZero() && now.Before(wm.time.Add(-consumeClockRegressionTolerance)) {
		return true
	}
	if now.After(wm.time) {
		wm.time = now
	}
	return false
}
