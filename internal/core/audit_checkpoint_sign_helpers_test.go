package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mustSignCheckpoint signs cp under the current seal binding (trusted in the
// tests that use it).
func mustSignCheckpoint(t testing.TB, c *KeyorixCore, cp *models.AuditCheckpoint) string {
	t.Helper()
	sig, err := c.signCheckpoint(cp)
	require.NoError(t, err)
	return sig
}

// mustSignCheckpointUnder signs cp under the trusted seal binding b.
func mustSignCheckpointUnder(t testing.TB, c *KeyorixCore, cp *models.AuditCheckpoint, b auditSealBinding) string {
	t.Helper()
	sig, err := c.signCheckpointUnder(cp, b)
	require.NoError(t, err)
	return sig
}
