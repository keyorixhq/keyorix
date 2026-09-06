package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNotifyRotationFailures_PayloadIsAllowlisted is Group 1's guard for
// notifyRotationFailures: the NotificationEvent it hands to
// WebhookSink/ChatSink (both of which serialize/forward the event
// essentially verbatim to an external, third-party endpoint) must be built
// from an explicit allowlist -- secret name plus a generic phrase -- and must
// NEVER include the upstream RotationBackend name, RotationRef (an IAM
// username/DB role/service-account email), or raw upstream error text, no
// matter how rich that detail is in the internal bookkeeping
// (rotationFailureDetail.Detail, which still reaches the audit trail and the
// rotation-state API -- both internal to Keyorix, out of scope for this
// guard).
//
// This exercises notifyRotationFailures directly with a crafted
// rotationFailureDetail whose Detail field deliberately embeds exactly the
// kind of connection/credential-adjacent text the real backend-rotation
// failure paths in rotateOneSecret produce (see rotation_executor.go), so it
// does not depend on any particular upstream backend's error wording.
func TestNotifyRotationFailures_PayloadIsAllowlisted(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	sink := &fakeSink{}
	c.SetNotificationSink(sink)

	const secretName = "prod-db-password"
	const sensitiveDetail = `via backend "aws-iam" ref "arn:aws:iam::123456789012:user/svc-app": ` +
		`AccessDenied: User arn:aws:sts::123456789012:assumed-role/deploy is not authorized ` +
		`(password=hunter2, host=db.internal.example.com)`

	failed := map[uint]rotationFailureDetail{
		1: {SecretName: secretName, Detail: sensitiveDetail},
	}
	c.notifyRotationFailures(context.Background(), 42, failed)

	require.Len(t, sink.events, 1, "one broadcast for the project's failures")
	msg := sink.events[0].Message

	assert.Contains(t, msg, secretName, "the secret name is allowlisted and must still appear")
	assert.NotContains(t, msg, "aws-iam", "the upstream backend name must never reach an external channel")
	assert.NotContains(t, msg, "arn:aws:iam::123456789012:user/svc-app", "the upstream ref must never reach an external channel")
	assert.NotContains(t, msg, "AccessDenied", "raw upstream error text must never reach an external channel")
	assert.NotContains(t, msg, "hunter2", "a credential-shaped fragment embedded in the raw error must never reach an external channel")
	assert.NotContains(t, msg, "db.internal.example.com", "a hostname embedded in the raw error must never reach an external channel")
	assert.NotContains(t, msg, sensitiveDetail, "the internal Detail field must never be interpolated into the external message wholesale")
}
