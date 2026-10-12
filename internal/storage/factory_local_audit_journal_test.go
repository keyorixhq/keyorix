package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

// TestLocalAuditJournal_OffByDefault pins the gate on ADR-115's prototype:
// the zero-value config leaves the journal disabled, and with it disabled
// the factory hook returns before touching the store at all (a nil store
// here would panic on any use). With the journal off, logAuditEvent's only
// difference from main is a nil-field check, so the default audit path is
// unchanged.
func TestLocalAuditJournal_OffByDefault(t *testing.T) {
	var cfg config.Config
	require.False(t, cfg.LocalAuditJournal.Enabled, "local_audit_journal.enabled must default to false")
	require.NoError(t, enableLocalAuditJournalIfConfigured(nil, &cfg))
}

// TestLocalAuditJournal_RefusesIncompleteOrConflictingConfig: when enabled,
// directory and replica_id are required, and the journal cannot be combined
// with ADR-112 Amendment 1's fast audit mode, whose "in effect" status would
// otherwise be reported while the journal fsync is what callers wait on.
// Every refusal happens before the store is touched.
func TestLocalAuditJournal_RefusesIncompleteOrConflictingConfig(t *testing.T) {
	base := func() *config.Config {
		var c config.Config
		c.LocalAuditJournal = config.LocalAuditJournalConfig{Enabled: true, Directory: "/var/lib/keyorix/journal", ReplicaID: "r1"}
		c.Storage.Type = "postgres"
		return &c
	}

	c := base()
	c.LocalAuditJournal.Directory = ""
	require.ErrorContains(t, enableLocalAuditJournalIfConfigured(nil, c), "directory is not set")

	c = base()
	c.LocalAuditJournal.ReplicaID = ""
	require.ErrorContains(t, enableLocalAuditJournalIfConfigured(nil, c), "replica_id is not set")

	c = base()
	c.Storage.Database.InsecureAuditSkipDurableSync = true
	require.True(t, c.Storage.Database.AuditDurableSyncStatus(c.Storage.Type).InEffect, "precondition: fast mode in effect on postgres")
	require.ErrorContains(t, enableLocalAuditJournalIfConfigured(nil, c), "cannot be combined")
}
