package encryption

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chunkTestData returns an EncryptionService and a plaintext that spans several chunks at
// the given chunk size.
func chunkTestData(t *testing.T, chunkSize, total int) (*EncryptionService, []byte) {
	t.Helper()
	es := newTestEncryptionService(t)
	pt := make([]byte, total)
	_, err := rand.Read(pt)
	require.NoError(t, err)
	return es, pt
}

// TestChunked_RoundTrip is the positive control: untouched chunks reassemble exactly,
// including when delivered out of slice order (reassembly is by authenticated index).
func TestChunked_RoundTrip(t *testing.T) {
	es, pt := chunkTestData(t, 1024, 5*1024) // 5 chunks
	chunks, err := es.EncryptChunked(pt, 1024, testKeyVersion)
	require.NoError(t, err)
	require.Len(t, chunks, 5)

	// Shuffle the slice order — order in the slice must not matter, only the index does.
	chunks[0], chunks[4] = chunks[4], chunks[0]
	got, err := es.DecryptChunked(chunks)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(pt, got), "untouched chunks must reassemble exactly")
}

// TestChunked_ReorderFailsClosed pins anti-reorder: swapping two chunks' ciphertext while
// leaving the index metadata in place must fail, not silently reassemble scrambled
// plaintext. The chunk index is bound into each chunk's AAD, so a chunk decrypted at the
// wrong position fails the GCM tag check.
func TestChunked_ReorderFailsClosed(t *testing.T) {
	es, pt := chunkTestData(t, 1024, 3*1024)
	chunks, err := es.EncryptChunked(pt, 1024, testKeyVersion)
	require.NoError(t, err)

	// Swap the ciphertext (and nonce) of chunks 0 and 1 but keep their index labels: now
	// the bytes sealed for index 1 sit under index 0's metadata.
	chunks[0].Data, chunks[1].Data = chunks[1].Data, chunks[0].Data
	chunks[0].Metadata.Nonce, chunks[1].Metadata.Nonce = chunks[1].Metadata.Nonce, chunks[0].Metadata.Nonce

	_, err = es.DecryptChunked(chunks)
	require.Error(t, err, "a chunk decrypted at the wrong index must fail the AAD check")
}

// TestChunked_TruncationFailsClosed pins anti-truncation: dropping the last chunk and
// editing the (unauthenticated) TotalChunks on the survivors to match must fail. The total
// is bound into every chunk's AAD, so a shorter claimed total no longer matches what was
// sealed.
func TestChunked_TruncationFailsClosed(t *testing.T) {
	es, pt := chunkTestData(t, 1024, 4*1024) // 4 chunks
	chunks, err := es.EncryptChunked(pt, 1024, testKeyVersion)
	require.NoError(t, err)
	require.Len(t, chunks, 4)

	// Drop the last chunk and rewrite TotalChunks on the rest so the count check passes.
	truncated := chunks[:3]
	for _, c := range truncated {
		c.Metadata.TotalChunks = 3
	}

	_, err = es.DecryptChunked(truncated)
	require.Error(t, err, "a truncated chunk set must fail even after editing TotalChunks")
}

// TestChunked_CrossStreamSpliceFailsClosed pins anti-splice: substituting a chunk from a
// different chunked secret (a different stream) for one of this secret's chunks must fail —
// even if the attacker rewrites the spliced chunk's index and stream-id metadata to match,
// because the stream id is bound into the AAD it was sealed with.
func TestChunked_CrossStreamSpliceFailsClosed(t *testing.T) {
	es, ptA := chunkTestData(t, 1024, 3*1024)
	a, err := es.EncryptChunked(ptA, 1024, testKeyVersion)
	require.NoError(t, err)

	ptB := make([]byte, 3*1024)
	_, err = rand.Read(ptB)
	require.NoError(t, err)
	b, err := es.EncryptChunked(ptB, 1024, testKeyVersion)
	require.NoError(t, err)

	// Splice B's chunk 1 into A in place of A's chunk 1.
	t.Run("naive splice is caught by the stream-id consistency check", func(t *testing.T) {
		spliced := []*EncryptedData{a[0], b[1], a[2]}
		_, err := es.DecryptChunked(spliced)
		require.Error(t, err, "a chunk from another stream must be rejected")
	})

	t.Run("relabeled splice is caught by the AAD", func(t *testing.T) {
		// Rewrite B's chunk-1 metadata to impersonate A's chunk 1 (same stream id + index
		// + total). The metadata now passes the consistency checks, but the chunk was
		// sealed under B's stream id, so the rebuilt AAD no longer matches.
		victim := *b[1]
		victim.Metadata.ChunkStreamID = a[0].Metadata.ChunkStreamID
		victim.Metadata.ChunkIndex = 1
		victim.Metadata.TotalChunks = a[0].Metadata.TotalChunks
		spliced := []*EncryptedData{a[0], &victim, a[2]}
		_, err := es.DecryptChunked(spliced)
		require.Error(t, err, "a relabeled foreign chunk must still fail the AAD check")
	})
}

// TestChunked_DuplicateIndexFailsClosed pins that a set padded with a duplicated chunk
// (instead of the real one at another index) is rejected rather than dropping data.
func TestChunked_DuplicateIndexFailsClosed(t *testing.T) {
	es, pt := chunkTestData(t, 1024, 3*1024)
	chunks, err := es.EncryptChunked(pt, 1024, testKeyVersion)
	require.NoError(t, err)

	// Replace chunk 2 with a second copy of chunk 0 (count still matches TotalChunks).
	dup := []*EncryptedData{chunks[0], chunks[1], chunks[0]}
	_, err = es.DecryptChunked(dup)
	require.Error(t, err, "a duplicated chunk index must be rejected")
}
