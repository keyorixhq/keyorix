package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// WithSchedulerLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithSchedulerLock(ctx context.Context, _ int64, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

// TryAcquireSchedulerLock/ReleaseSchedulerLock are no-ops in tests (single
// instance, nothing to contend with) — mirrors WithSchedulerLock above.
func (m *MockStorage) TryAcquireSchedulerLock(_ context.Context, _ int64, _ string, _ time.Duration) (bool, error) {
	return true, nil
}
func (m *MockStorage) ReleaseSchedulerLock(_ context.Context, _ int64, _ string) error {
	return nil
}

// WithAuditCheckpointLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithAuditCheckpointLock(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// WithBootstrapLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithBootstrapLock(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// WithNamedLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithNamedLock(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// WithTransaction runs fn directly against the mock (no real transaction in tests).
func (m *MockStorage) WithTransaction(_ context.Context, fn func(storage.Storage) error) error {
	return fn(m)
}

// LockLiveProject answers "live" (#2702/#2710/#2711/#2712). This mock has no
// projects at all, and every test using it exercises a path where the project's
// existence is not the subject — answering false would make the create paths
// that now re-check it fail for a reason none of those tests is about.
//
// Note what this costs: a mock-backed test can never observe the deleted-parent
// rollback. That is deliberate, and it is why the proof for this fix is the four
// cross-replica Postgres tests in
// concurrency_child_under_deleted_project_postgres_test.go against real storage
// and a real row lock, not anything here — a mock cannot model a row lock, and a
// mock that returned a canned false would test the error message, not the race.
func (m *MockStorage) LockLiveProject(_ context.Context, _ uint) (bool, error) { return true, nil }
