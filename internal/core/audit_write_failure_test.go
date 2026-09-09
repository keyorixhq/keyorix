package core

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// captureLog redirects the standard logger's output for the duration of fn and
// returns everything written to it.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	fn()
	return buf.String()
}

// fakeAuditForwarder records every event handed to Forward, so tests can assert
// whether emitAudit called it.
type fakeAuditForwarder struct {
	forwarded []*models.AuditEvent
}

func (f *fakeAuditForwarder) Forward(event *models.AuditEvent) {
	f.forwarded = append(f.forwarded, event)
}

// --- #382: a failed local audit write must be logged loudly, and must NOT be
// forwarded to the SIEM (the DB stays authoritative; a never-persisted event
// must not leak off-box either). ---

func TestEmitAudit_StorageFailure_LogsWarningAndSkipsSIEMForward(t *testing.T) {
	ms := new(MockStorage)
	storageErr := errors.New("disk full")
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(storageErr)

	fwd := &fakeAuditForwarder{}
	c := &KeyorixCore{storage: ms, auditForwarder: fwd, auditStream: newAuditBroker()}

	event := &models.AuditEvent{EventType: "secret.read", Description: "User alice read secret db-password"}

	logged := captureLog(t, func() {
		c.emitAudit(context.Background(), event)
	})

	assert.Contains(t, logged, "SECURITY", "a failed audit write must be logged loudly, not silently swallowed")
	assert.Contains(t, logged, "secret.read")
	assert.Empty(t, fwd.forwarded, "must not forward to SIEM when the local write failed — DB stays authoritative")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

func TestEmitAudit_StorageSuccess_ForwardsToSIEMAndDoesNotWarn(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	fwd := &fakeAuditForwarder{}
	c := &KeyorixCore{storage: ms, auditForwarder: fwd, auditStream: newAuditBroker()}

	event := &models.AuditEvent{EventType: "secret.read"}

	logged := captureLog(t, func() {
		c.emitAudit(context.Background(), event)
	})

	assert.NotContains(t, logged, "SECURITY", "a successful audit write must not emit a failure warning")
	require.Len(t, fwd.forwarded, 1, "a durably persisted event must still reach the SIEM")
	assert.Same(t, event, fwd.forwarded[0])
}

func TestWriteAccessLog_StorageFailure_LogsWarning(t *testing.T) {
	ms := new(MockStorage)
	storageErr := errors.New("connection exhausted")
	ms.On("CreateSecretAccessLog", mock.Anything, mock.Anything).Return(storageErr)

	c := &KeyorixCore{storage: ms}

	logged := captureLog(t, func() {
		c.writeAccessLog(context.Background(), 42, "alice", "read", "10.0.0.1", "curl/8")
	})

	assert.Contains(t, logged, "SECURITY", "a failed access-log write must be logged loudly, not silently swallowed")
	ms.AssertCalled(t, "CreateSecretAccessLog", mock.Anything, mock.Anything)
}

func TestWriteAccessLog_StorageSuccess_DoesNotWarn(t *testing.T) {
	ms := new(MockStorage)
	ms.On("CreateSecretAccessLog", mock.Anything, mock.Anything).Return(nil)

	c := &KeyorixCore{storage: ms}

	logged := captureLog(t, func() {
		c.writeAccessLog(context.Background(), 42, "alice", "read", "10.0.0.1", "curl/8")
	})

	assert.NotContains(t, logged, "SECURITY")
}

// --- #381: Description/Diff must be capped, independent of secret_name_policy. ---

func TestEmitAudit_TruncatesOversizedDescriptionAndDiff(t *testing.T) {
	ms := new(MockStorage)
	var persisted *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			persisted = args.Get(1).(*models.AuditEvent)
		}).
		Return(nil)

	c := &KeyorixCore{storage: ms, auditStream: newAuditBroker()}

	// Simulate an attacker-chosen secret name (no length cap unless
	// secret_name_policy is configured) flowing into a Description, and an
	// oversized Diff.
	hugeName := strings.Repeat("A", 10*1024*1024) // 10 MiB, matches the global body-size cap
	event := &models.AuditEvent{
		EventType:   "secret.read",
		Description: "User alice read secret " + hugeName,
		Diff:        strings.Repeat("d", 100*1024),
	}

	c.emitAudit(context.Background(), event)

	require.NotNil(t, persisted)
	assert.LessOrEqual(t, len(persisted.Description), auditDescriptionMaxLen+len(auditTruncatedMarker))
	assert.LessOrEqual(t, len(persisted.Diff), auditDiffMaxLen+len(auditTruncatedMarker))
	assert.True(t, strings.HasSuffix(persisted.Description, auditTruncatedMarker), "truncated Description must carry the marker")
	assert.True(t, strings.HasSuffix(persisted.Diff, auditTruncatedMarker), "truncated Diff must carry the marker")
	// The event handed to the caller is mutated in place too (same pointer),
	// so nothing downstream (e.g. a SIEM forward) can observe the unbounded value.
	assert.True(t, strings.HasSuffix(event.Description, auditTruncatedMarker))
}

func TestEmitAudit_NormalLengthDescriptionAndDiffUnaffected(t *testing.T) {
	ms := new(MockStorage)
	var persisted *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			persisted = args.Get(1).(*models.AuditEvent)
		}).
		Return(nil)

	c := &KeyorixCore{storage: ms, auditStream: newAuditBroker()}

	desc := "User alice read secret db-password"
	diff := `{"name":{"old":"db-password","new":"db-password-2"}}`
	event := &models.AuditEvent{
		EventType:   "secret.updated",
		Description: desc,
		Diff:        diff,
	}

	c.emitAudit(context.Background(), event)

	require.NotNil(t, persisted)
	assert.Equal(t, desc, persisted.Description, "a normal-length description must pass through unchanged")
	assert.Equal(t, diff, persisted.Diff, "a normal-length diff must pass through unchanged")
}

func TestTruncateAuditField(t *testing.T) {
	assert.Equal(t, "short", truncateAuditField("short", 100))

	long := strings.Repeat("x", 50)
	got := truncateAuditField(long, 10)
	assert.Equal(t, 10+len(auditTruncatedMarker), len(got))
	assert.True(t, strings.HasPrefix(got, strings.Repeat("x", 10)))
	assert.True(t, strings.HasSuffix(got, auditTruncatedMarker))

	// Multi-byte rune sitting exactly on the cut boundary must not be split
	// into an invalid UTF-8 sequence.
	multibyte := strings.Repeat("a", 9) + "€" // '€' is 3 bytes (U+20AC)
	truncatedMB := truncateAuditField(multibyte, 10)
	assert.True(t, strings.HasPrefix(truncatedMB, strings.Repeat("a", 9)))
	assert.False(t, strings.Contains(truncatedMB[:len(truncatedMB)-len(auditTruncatedMarker)], "€"))
}
