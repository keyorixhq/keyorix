package core

// alert_escalation_channel_read_fault_test.go -- CORE-FAULT-TAILS-1 item 4 (REVIEW-3972-DEEP-2):
// GetNotificationChannel answers a storage read fault as ErrStorageReadUnavailable, whose
// text is the fixed client-safe sentence, so the escalation dispatcher's "%v" log line
// lost the driver cause. It logs StorageReadFaultDetail now, and a failed channel read
// still does not count the alert as escalated.

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRunAlertEscalation_ChannelReadFaultLogsCauseAndDoesNotEscalate(t *testing.T) {
	store := new(MockStorage)
	now := time.Now().UTC()
	p := makePolicy(1, "p1", "low", 30)
	p.ChannelIDs = "7"
	alert := makeAlert(1, "low", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return((*models.NotificationChannel)(nil),
		fmt.Errorf("dial tcp 10.0.0.5:5432 (injected-cause): %w", syscall.ECONNREFUSED))
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // the job's run row
	c := NewKeyorixCore(store)
	c.now = fixedNow(now)

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	result, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Evaluated)
	assert.Equal(t, 0, result.Escalated, "a channel that could not be read received nothing")
	assert.Equal(t, 1, result.Skipped)

	out := buf.String()
	assert.Contains(t, out, "alert escalation: policy 1: channel 7:")
	assert.Contains(t, out, "injected-cause", "the server log keeps the driver cause: %s", out)
	store.AssertExpectations(t)
}
