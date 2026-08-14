package main

import (
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// fakeClosingForwarder is a minimal core.AuditForwarder that also implements
// Close(), mirroring *siem.Forwarder's shape without pulling in the real
// package (spool files, HTTP delivery) for a pure wiring test.
type fakeClosingForwarder struct{ closed bool }

func (f *fakeClosingForwarder) Forward(_ *models.AuditEvent) {}
func (f *fakeClosingForwarder) Close()                       { f.closed = true }

// fakeForwarderNoClose implements only Forward — the narrow core.AuditForwarder
// interface — with no Close method at all, exercising the "not a closer" branch.
type fakeForwarderNoClose struct{}

func (f *fakeForwarderNoClose) Forward(_ *models.AuditEvent) {}

func newTestCoreService(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// TestCloseAuditForwarder_ClosesWiredForwarder is #G56: nothing previously called
// Forwarder.Close() at shutdown, so the SIEM forwarder's in-memory queue was never
// flushed/drained before the process exited. This proves closeAuditForwarder
// actually reaches and invokes Close() on whatever was wired via SetAuditForwarder.
func TestCloseAuditForwarder_ClosesWiredForwarder(t *testing.T) {
	coreService := newTestCoreService(t)
	fake := &fakeClosingForwarder{}
	coreService.SetAuditForwarder(fake)

	closeAuditForwarder(coreService)

	if !fake.closed {
		t.Fatal("closeAuditForwarder did not call Close() on the wired forwarder")
	}
}

// TestCloseAuditForwarder_NilForwarderNoPanic covers the common case (no
// audit.siem block configured) — closeAuditForwarder must be a safe no-op.
func TestCloseAuditForwarder_NilForwarderNoPanic(t *testing.T) {
	closeAuditForwarder(newTestCoreService(t))
}

// TestCloseAuditForwarder_ForwarderWithoutCloseNoPanic covers a hypothetical
// AuditForwarder implementation that only satisfies the narrow Forward-only
// interface (no Close method) — the type assertion in closeAuditForwarder must
// fail gracefully, not panic.
func TestCloseAuditForwarder_ForwarderWithoutCloseNoPanic(t *testing.T) {
	coreService := newTestCoreService(t)
	coreService.SetAuditForwarder(&fakeForwarderNoClose{})
	closeAuditForwarder(coreService)
}
