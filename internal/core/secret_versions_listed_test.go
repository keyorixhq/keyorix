package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUDIT-UX-2 item 3: a version listing shows on the dashboard as its own type
// with the secret's name (from LogSecretVersionsListed's description), not as
// "accessed" (which is a value read) and not as the raw event type.
func TestMapAuditEventToActivity_VersionsListed(t *testing.T) {
	t.Parallel()
	e := &models.AuditEvent{ID: 12, EventType: EventSecretVersionsListed, Description: "User alice listed the versions of secret db-pass", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "alice")
	assert.Equal(t, "versions_listed", item.Type)
	assert.Equal(t, "db-pass", item.SecretName)
}

// AUDIT-UX-3 item 1: a by-name lookup is shown as its own type, not "accessed".
func TestMapAuditEventToActivity_MetadataRead(t *testing.T) {
	t.Parallel()
	e := &models.AuditEvent{ID: 13, EventType: EventSecretMetadataRead, Description: "User alice looked up secret db-pass", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "alice")
	assert.Equal(t, "metadata_read", item.Type)
	assert.Equal(t, "db-pass", item.SecretName)
}
