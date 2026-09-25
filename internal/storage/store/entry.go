// Package store handles secret persistence via direct GORM database access.
//
// # Domain
//
// LocalStorage implements the core [storage.Storage] interface by accessing
// the database directly via GORM. Used by the server itself and for
// air-gapped / offline deployments.
//
// A second backend, RemoteStorage (proxying operations to a running Keyorix
// server via the REST API, used by the pre-ADR-108 thick CLI), was deleted
// entirely in ADR-108 Phase 6 step 14b-2 once the CLI switch (Phase 5) made
// it unreachable in any supported deployment. Each operation file that used
// to pair a remote_*.go with a local_*.go now stands alone.
//
// # Entry Point
//
// Start here. Read this comment, then open the single operation file you need.
// You do NOT need to read all files — each file is self-contained.
package store

import (
	"strings"
	"sync"
	"time"

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
	// non-Postgres backend (SQLite, single-process by construction): a registry
	// handing out one *sync.Mutex per lock key, mirroring PostgreSQL's
	// per-key pg_advisory_lock semantics exactly (see WithNamedLock's own doc
	// comment, FIX-5) rather than one shared mutex serializing every unrelated
	// key against every other. A pointer for the same sharing reason as every
	// other mutex on this struct.
	namedLockMu *namedLockRegistry
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
		namedLockMu:           newNamedLockRegistry(),
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
//
// Part 2 regression audit continuation (2026-09-04): .UTC() below strips any
// monotonic clock reading now carries -- both real callers named above
// (c.now()==time.Now, and a bare time.Now()) attach one. Two monotonic-
// carrying values compare using ONLY their monotonic delta (see time.Time's
// package doc), which never regresses even when the OS wall clock steps
// backward, so this comparison could never actually detect the regression
// it exists to catch without this. Same root cause as
// checkSecretExpiryClockNotRegressed's identical fix (internal/core/versions.go,
// #1635) and this function's own new authEffectiveNow sibling
// (internal/core/auth.go) -- fixed in all three at once, same underlying bug.
func (ls *LocalStorage) consumeClockLooksRegressed(now time.Time) bool {
	now = now.UTC()
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
