package auditverify

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// INV-AUDITVERIFY-04: the persisted high-water-mark and retention-anchor
// values are joined with \x1f (ASCII unit separator), never \x00 — a
// PostgreSQL text/varchar column rejects an embedded NUL outright, and both
// values are stored as plain strings via SetSystemMetadata. (The HMAC'd
// canonical strings, checkpointCanonical/retentionAnchorCanonical, DO use
// \x00 — they are hashed, never persisted — so this test pins only the
// persisted layouts.)
//
// What this does not cover: that internal/core's writer uses the same byte.
// core keeps its own auditHighWaterSep/auditRetentionAnchorSep constants
// (internal/core/audit_checkpoint.go, audit_retention_anchor.go); this test
// pins only this package's copy and its encode/parse behaviour.

func TestPersistedSeparators_AreUnitSeparatorNotNUL(t *testing.T) {
	assert.Equal(t, "\x1f", auditHighWaterSep, "high-water separator must be \\x1f")
	assert.Equal(t, "\x1f", auditRetentionAnchorSep, "retention-anchor separator must be \\x1f")
}

func TestEncodeHighWater_UsesUnitSeparatorAndNoNUL(t *testing.T) {
	cp := &Checkpoint{ChainedEvents: 42, HeadID: 7, HeadHash: "abc123", KeyVersion: "k1"}
	val := EncodeHighWater(cp, "deadbeef")

	assert.NotContains(t, val, "\x00", "a persisted high-water value must never contain NUL (Postgres text rejects it)")
	assert.Equal(t, "v1\x1f42\x1f7\x1fabc123\x1fk1\x1fdeadbeef", val)

	got, sig, ok := ParseHighWater(val)
	require.True(t, ok)
	assert.Equal(t, cp, got)
	assert.Equal(t, "deadbeef", sig)
}

func TestParseHighWater_RejectsNULSeparatedValue(t *testing.T) {
	nul := strings.Join([]string{"v1", "42", "7", "abc123", "k1", "deadbeef"}, "\x00")
	_, _, ok := ParseHighWater(nul)
	assert.False(t, ok, "a \\x00-separated high-water value must not parse")
}

func TestParseRetentionAnchor_UnitSeparatorAcceptedNULRejected(t *testing.T) {
	fields := []string{"v1", "9", "prevhash", "entryhash", "k1", "sig"}

	id, prev, entry, kv, sig, ok := ParseRetentionAnchor(strings.Join(fields, "\x1f"))
	require.True(t, ok, "a \\x1f-separated retention anchor must parse")
	assert.Equal(t, uint64(9), id)
	assert.Equal(t, "prevhash", prev)
	assert.Equal(t, "entryhash", entry)
	assert.Equal(t, "k1", kv)
	assert.Equal(t, "sig", sig)

	_, _, _, _, _, ok = ParseRetentionAnchor(strings.Join(fields, "\x00"))
	assert.False(t, ok, "a \\x00-separated retention anchor must not parse")
}
