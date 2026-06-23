package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// EncryptionService handles all encryption/decryption operations
type EncryptionService struct {
	kek []byte // Key Encryption Key
	gcm cipher.AEAD
}

// EncryptionMetadata contains metadata about encrypted data
type EncryptionMetadata struct {
	Algorithm   string    `json:"algorithm"`
	KeyVersion  string    `json:"key_version"`
	EncryptedAt time.Time `json:"encrypted_at"`
	Nonce       string    `json:"nonce"`
	Salt        string    `json:"salt,omitempty"`
	Iterations  int       `json:"iterations,omitempty"`
	ChunkIndex  int       `json:"chunk_index,omitempty"`
	TotalChunks int       `json:"total_chunks,omitempty"`
	// ChunkStreamID is a random per-encryption identifier shared by every chunk of one
	// chunked secret. With ChunkIndex/TotalChunks it is folded into each chunk's AAD
	// (chunkAAD), so a chunk cannot be reordered, dropped, or spliced in from another
	// chunked secret without failing the GCM tag check on decryption.
	ChunkStreamID string `json:"chunk_stream_id,omitempty"`
	AADVersion    string `json:"aad_version,omitempty"` // "v2" = secretID:projectID:versionNumber; absent = legacy (no AAD). ("v1" was the pre-migration secretID:namespaceID:versionNumber scheme; no longer produced.)
}

// EncryptedData represents encrypted content with metadata
type EncryptedData struct {
	Data     []byte             `json:"data"`
	Metadata EncryptionMetadata `json:"metadata"`
}

// NewEncryptionService creates a new encryption service with KEK
func NewEncryptionService(kek []byte) (*EncryptionService, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("KEK must be 32 bytes, got %d", len(kek))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptionService{
		kek: kek,
		gcm: gcm,
	}, nil
}

// GenerateKEK generates a new Key Encryption Key using PBKDF2
func GenerateKEK(password string, salt []byte, iterations int) []byte {
	if iterations == 0 {
		iterations = 100000 // Default iterations
	}
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

// GenerateRandomKey generates a cryptographically secure random key
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts data using AES-GCM with the KEK
func (es *EncryptionService) Encrypt(plaintext []byte, keyVersion string) (*EncryptedData, error) {
	nonce := make([]byte, es.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := es.gcm.Seal(nil, nonce, plaintext, nil)

	metadata := EncryptionMetadata{
		Algorithm:   "AES-256-GCM",
		KeyVersion:  keyVersion,
		EncryptedAt: time.Now().UTC(),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
	}

	return &EncryptedData{
		Data:     ciphertext,
		Metadata: metadata,
	}, nil
}

// Decrypt decrypts data using AES-GCM with the KEK
func (es *EncryptionService) Decrypt(encryptedData *EncryptedData) ([]byte, error) {
	if encryptedData.Metadata.Algorithm != "AES-256-GCM" { //nolint:goconst
		return nil, fmt.Errorf("unsupported algorithm: %s", encryptedData.Metadata.Algorithm)
	}

	nonce, err := base64.StdEncoding.DecodeString(encryptedData.Metadata.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	plaintext, err := es.gcm.Open(nil, nonce, encryptedData.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// SecretAAD returns the canonical Additional Authenticated Data for a secret version.
// Format: "keyorix:v2:<secretID>:<projectID>:<versionNumber>"
// This binds the ciphertext to a specific secret + project + version, preventing
// ciphertext transplant attacks (copying an encrypted value between rows).
func SecretAAD(secretID, projectID uint, versionNumber int) []byte {
	return []byte(fmt.Sprintf("keyorix:v2:%d:%d:%d", secretID, projectID, versionNumber))
}

// EncryptWithAAD encrypts data using AES-GCM with Additional Authenticated Data.
// The AAD is mixed into the GCM authentication tag — it is not stored in the
// ciphertext but must be supplied identically on decryption.
func (es *EncryptionService) EncryptWithAAD(plaintext []byte, keyVersion string, aad []byte) (*EncryptedData, error) {
	nonce := make([]byte, es.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := es.gcm.Seal(nil, nonce, plaintext, aad)

	metadata := EncryptionMetadata{
		Algorithm:   "AES-256-GCM",
		KeyVersion:  keyVersion,
		EncryptedAt: time.Now().UTC(),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		AADVersion:  "v2",
	}

	return &EncryptedData{
		Data:     ciphertext,
		Metadata: metadata,
	}, nil
}

// DecryptWithAAD decrypts data encrypted with EncryptWithAAD.
// Returns an error if the AAD does not match — this catches ciphertext transplants.
func (es *EncryptionService) DecryptWithAAD(encryptedData *EncryptedData, aad []byte) ([]byte, error) {
	if encryptedData.Metadata.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported algorithm: %s", encryptedData.Metadata.Algorithm)
	}

	nonce, err := base64.StdEncoding.DecodeString(encryptedData.Metadata.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	plaintext, err := es.gcm.Open(nil, nonce, encryptedData.Data, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data (AAD mismatch or corruption): %w", err)
	}

	return plaintext, nil
}

// EncryptChunked encrypts large data by splitting it into chunks
func (es *EncryptionService) EncryptChunked(plaintext []byte, chunkSize int, keyVersion string) ([]*EncryptedData, error) {
	if chunkSize <= 0 {
		chunkSize = 64 * 1024 // Default 64KB chunks
	}

	// A random per-call stream ID binds every chunk to THIS encryption. Together with the
	// chunk index and total, folded into each chunk's AAD, it makes reorder, truncation,
	// and cross-stream splice all fail the GCM tag check on decryption — the chunk index
	// and total in the (unauthenticated) metadata alone could otherwise be edited freely.
	streamIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, streamIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate chunk stream id: %w", err)
	}
	streamID := hex.EncodeToString(streamIDBytes)

	var chunks []*EncryptedData
	totalChunks := (len(plaintext) + chunkSize - 1) / chunkSize

	for i := 0; i < len(plaintext); i += chunkSize {
		end := i + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		idx := len(chunks)
		encryptedChunk, err := es.EncryptWithAAD(plaintext[i:end], keyVersion, chunkAAD(streamID, idx, totalChunks))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt chunk %d: %w", idx, err)
		}

		// Add chunk metadata. These values are also bound into the AAD above, so any
		// tampering with them is caught by DecryptWithAAD, not trusted blindly.
		encryptedChunk.Metadata.ChunkIndex = idx
		encryptedChunk.Metadata.TotalChunks = totalChunks
		encryptedChunk.Metadata.ChunkStreamID = streamID

		chunks = append(chunks, encryptedChunk)
	}

	return chunks, nil
}

// chunkAAD binds a chunk to its stream, position, and count. Reconstructed identically on
// decryption from the chunk's claimed metadata, so a reordered, truncated, or spliced-in
// chunk yields a different AAD than it was sealed with and fails the AES-GCM tag check.
func chunkAAD(streamID string, index, total int) []byte {
	return []byte(fmt.Sprintf("keyorix:chunk:v1:%s:%d:%d", streamID, index, total))
}

// DecryptChunked decrypts chunked data and reassembles it. Every chunk must belong to the
// same stream and agree on the total; the per-chunk AAD (stream+index+total) is the
// cryptographic backstop, so reorder, truncation, duplication, and cross-secret splice all
// fail closed rather than reassembling an attacker-chosen plaintext.
func (es *EncryptionService) DecryptChunked(chunks []*EncryptedData) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks provided")
	}

	totalChunks := chunks[0].Metadata.TotalChunks
	streamID := chunks[0].Metadata.ChunkStreamID
	if len(chunks) != totalChunks {
		return nil, fmt.Errorf("expected %d chunks, got %d", totalChunks, len(chunks))
	}

	// Sort chunks by index (they may arrive out of order), rejecting any inconsistency
	// before decryption; the AAD check below re-verifies the same facts cryptographically.
	sortedChunks := make([]*EncryptedData, totalChunks)
	for _, chunk := range chunks {
		if chunk.Metadata.ChunkStreamID != streamID {
			return nil, fmt.Errorf("chunk stream id mismatch (chunk spliced from another secret?)")
		}
		if chunk.Metadata.TotalChunks != totalChunks {
			return nil, fmt.Errorf("inconsistent total chunks across the set")
		}
		if chunk.Metadata.ChunkIndex < 0 || chunk.Metadata.ChunkIndex >= totalChunks {
			return nil, fmt.Errorf("invalid chunk index %d", chunk.Metadata.ChunkIndex)
		}
		if sortedChunks[chunk.Metadata.ChunkIndex] != nil {
			return nil, fmt.Errorf("duplicate chunk index %d", chunk.Metadata.ChunkIndex)
		}
		sortedChunks[chunk.Metadata.ChunkIndex] = chunk
	}

	// Decrypt and reassemble, binding each chunk to its position via the AAD.
	var result []byte
	for i, chunk := range sortedChunks {
		if chunk == nil {
			return nil, fmt.Errorf("missing chunk at index %d", i)
		}

		decrypted, err := es.DecryptWithAAD(chunk, chunkAAD(streamID, i, totalChunks))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		result = append(result, decrypted...)
	}

	return result, nil
}

// SerializeEncryptedData converts EncryptedData to JSON bytes
func SerializeEncryptedData(data *EncryptedData) ([]byte, error) {
	return json.Marshal(data)
}

// DeserializeEncryptedData converts JSON bytes to EncryptedData
func DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	var encrypted EncryptedData
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	return &encrypted, nil
}

// RotateKey re-encrypts data with a new key version
func (es *EncryptionService) RotateKey(encryptedData *EncryptedData, newKeyVersion string) (*EncryptedData, error) {
	// Decrypt with current key
	plaintext, err := es.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt for key rotation: %w", err)
	}

	// Re-encrypt with new key version
	return es.Encrypt(plaintext, newKeyVersion)
}
