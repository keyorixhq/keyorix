package auditverify

import (
	"context"
	"crypto/fips140"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// checkpointedChainDB seeds a two-row chain with a checkpoint over its head and
// a high-water mark, signed with a valid 32-byte key, and opens it read-only.
func checkpointedChainDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	seedEmptySchema(t, path)
	prev := GenesisHash
	for i := 1; i <= 2; i++ {
		row := &AuditEventRow{ID: uint64(i), EventType: "secret.read", IPAddress: "10.0.0.1", Description: "key length test",
			EventTime: time.Date(2027, 6, 1, 10, i, 0, 0, time.UTC), ActorType: "user", PrevHash: prev}
		row.EntryHash = ComputeEntryHash(row, prev)
		survivorInsertRow(t, path, row)
		prev = row.EntryHash
	}
	cp := &Checkpoint{ChainedEvents: 2, HeadID: 2, HeadHash: prev, KeyVersion: "v1"}
	cp.Signature = SignCheckpoint(cp, []byte(strings.Repeat("k", 32)))
	survivorInsertCheckpoint(t, path, cp, nil)
	// The high-water mark is the first thing Verify MACs under the supplied key.
	survivorSetMetadata(t, path, auditHighWaterKey, EncodeHighWater(cp, cp.Signature))
	db, err := OpenSQLiteReadOnly(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// FIPS-TAILS-2 item 4, red/green: under GODEBUG=fips140=only an operator
// checkpoint key of 1..13 bytes made crypto/hmac panic inside Verify. It is now
// a usage error naming MinKEKLen, for the current and for a previous key.
func TestVerify_UnderFIPS140Only_ShortCheckpointKeyIsUsageError(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; TestCheckCheckpointKeyLens_* cover default mode")
	}
	for name, opts := range map[string]Options{
		"current 1 byte":   {CheckpointKey: []byte("k")},
		"current 13 bytes": {CheckpointKey: []byte(strings.Repeat("k", 13))},
		"previous 5 bytes": {CheckpointKey: []byte(strings.Repeat("k", 32)), PreviousCheckpointKeys: [][]byte{[]byte("short")}},
	} {
		t.Run(name, func(t *testing.T) {
			db := checkpointedChainDB(t)
			var res *Result
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Verify panicked: %v", r)
					}
				}()
				res, err = Verify(context.Background(), db, opts)
			}()
			require.Error(t, err, "want a usage error, got verdict %v", res)
			require.Contains(t, err.Error(), "MinKEKLen (14 bytes")
		})
	}
	// The signing key itself is not refused and authenticates the checkpoint.
	res, err := Verify(context.Background(), checkpointedChainDB(t), Options{CheckpointKey: []byte(strings.Repeat("k", 32))})
	require.NoError(t, err)
	require.True(t, res.Checkpoint.Authenticated, "verdict %v: %s", res.Verdict, res.Reason)
}
