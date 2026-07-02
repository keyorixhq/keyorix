package core

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// captureLog runs fn with the standard logger redirected to a buffer, returning
// what was logged.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// #216: a failed audit-event write must be surfaced loudly (operator-visible via
// logs), not silently discarded — the triggering action (a secret read, role grant,
// etc.) already succeeded, so nothing else would ever reveal a DB-down/disk-full/
// pool-exhaustion audit-write failure. A lost write here leaves no hole for
// VerifyAuditChain to detect either, since nothing was ever inserted.
func TestEmitAudit_StorageErrorIsLoudlyLogged(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(errors.New("db connection pool exhausted"))

	out := captureLog(t, func() {
		ok := true
		c.emitAudit(context.Background(), &models.AuditEvent{
			EventType: "secret.read", Success: &ok,
		})
	})

	if !strings.Contains(out, "secret.read") {
		t.Errorf("log missing the event type for operator diagnosis; got: %s", out)
	}
	if !strings.Contains(out, "db connection pool exhausted") {
		t.Errorf("log missing the underlying storage error; got: %s", out)
	}
}

// #216: a failed secret-access-log write (the parallel writer alongside the audit
// event, previously a bare `_ = c.storage.CreateSecretAccessLog(...)`) must likewise
// be surfaced loudly, not silently discarded.
func TestWriteAccessLog_StorageErrorIsLoudlyLogged(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	store.On("CreateSecretAccessLog", mock.Anything, mock.Anything).Return(errors.New("disk full"))

	out := captureLog(t, func() {
		c.writeAccessLog(context.Background(), 42, "alice", "read", "10.0.0.1", "curl/8")
	})

	if !strings.Contains(out, "42") {
		t.Errorf("log missing the secret ID for operator diagnosis; got: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("log missing the actor for operator diagnosis; got: %s", out)
	}
	if !strings.Contains(out, "disk full") {
		t.Errorf("log missing the underlying storage error; got: %s", out)
	}
}
