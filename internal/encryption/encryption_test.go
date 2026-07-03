package encryption

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

const testKeyVersion = "test-v1"

// GenerateKEK's 0-iterations fallback must use a current-best-practice PBKDF2-SHA256
// iteration count (OWASP's 2023+ minimum is 600,000), not the older, materially
// weaker 100,000 default. This also pins that the fallback stays in sync with
// KeyManager.deriveKEK's legacy passphrase path, which derives explicitly at
// DefaultKEKIterations.
func TestGenerateKEK_DefaultIterationsMeetsOWASPMinimum(t *testing.T) {
	const owaspMinimum = 600000
	if DefaultKEKIterations < owaspMinimum {
		t.Fatalf("DefaultKEKIterations = %d, want >= %d (OWASP PBKDF2-HMAC-SHA256 minimum)", DefaultKEKIterations, owaspMinimum)
	}

	password, salt := "correct horse battery staple", []byte("0123456789abcdef")
	got := GenerateKEK(password, salt, 0)
	want := pbkdf2.Key([]byte(password), salt, DefaultKEKIterations, 32, sha256.New)
	if !bytes.Equal(got, want) {
		t.Error("iterations=0 must derive with DefaultKEKIterations, not a weaker fallback")
	}

	// A caller-specified iteration count is still honored (never silently overridden).
	custom := GenerateKEK(password, salt, 1000)
	if bytes.Equal(custom, got) {
		t.Error("an explicit non-zero iteration count must not be replaced by the default")
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Generate another key and ensure they're different
	key2, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate second random key: %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Error("Generated keys should be different")
	}
}

func TestEncryptionService(t *testing.T) {
	// Generate a test KEK
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	// Create encryption service
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}

	// Test data
	plaintext := []byte("This is a test secret message!")
	keyVersion := testKeyVersion

	// Encrypt
	encrypted, err := service.Encrypt(plaintext, keyVersion)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify metadata
	if encrypted.Metadata.Algorithm != "AES-256-GCM" { //nolint:goconst
		t.Errorf("Expected algorithm AES-256-GCM, got %s", encrypted.Metadata.Algorithm)
	}

	if encrypted.Metadata.KeyVersion != keyVersion {
		t.Errorf("Expected key version %s, got %s", keyVersion, encrypted.Metadata.KeyVersion)
	}

	// Decrypt
	decrypted, err := service.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decrypted data matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", plaintext, decrypted)
	}
}

// A corrupt/wrong-length stored nonce must yield an ERROR, not a panic (gcm.Open panics
// on a wrong-length nonce; the guard converts that to a clean error).
func TestDecrypt_RejectsBadNonceLengthWithoutPanic(t *testing.T) {
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}
	enc, err := service.Encrypt([]byte("secret"), testKeyVersion)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	// Corrupt the nonce to a too-short value (base64 of 4 bytes).
	enc.Metadata.Nonce = base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})

	_, err = service.Decrypt(enc) // must not panic
	if err == nil {
		t.Fatal("expected an error for a wrong-length nonce")
	}

	// Same guard on the AAD path.
	encAAD, err := service.EncryptWithAAD([]byte("secret"), testKeyVersion, []byte("aad"))
	if err != nil {
		t.Fatalf("Failed to encrypt with AAD: %v", err)
	}
	encAAD.Metadata.Nonce = base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})
	if _, err := service.DecryptWithAAD(encAAD, []byte("aad")); err == nil {
		t.Fatal("expected an error for a wrong-length nonce on the AAD path")
	}
}

func TestChunkedEncryption(t *testing.T) {
	// Generate a test KEK
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	// Create encryption service
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}

	// Create test data larger than chunk size
	plaintext := make([]byte, 150*1024) // 150KB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	keyVersion := testKeyVersion
	chunkSize := 64 * 1024 // 64KB chunks

	// Encrypt with chunking
	chunks, err := service.EncryptChunked(plaintext, chunkSize, keyVersion)
	if err != nil {
		t.Fatalf("Failed to encrypt chunked: %v", err)
	}

	// Verify we got the expected number of chunks
	expectedChunks := (len(plaintext) + chunkSize - 1) / chunkSize
	if len(chunks) != expectedChunks {
		t.Errorf("Expected %d chunks, got %d", expectedChunks, len(chunks))
	}

	// Verify chunk metadata
	for i, chunk := range chunks {
		if chunk.Metadata.ChunkIndex != i {
			t.Errorf("Chunk %d has wrong index %d", i, chunk.Metadata.ChunkIndex)
		}
		if chunk.Metadata.TotalChunks != expectedChunks {
			t.Errorf("Chunk %d has wrong total chunks %d, expected %d", i, chunk.Metadata.TotalChunks, expectedChunks)
		}
	}

	// Decrypt chunked data
	decrypted, err := service.DecryptChunked(chunks)
	if err != nil {
		t.Fatalf("Failed to decrypt chunked: %v", err)
	}

	// Verify decrypted data matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted chunked data doesn't match original. Lengths: original=%d, decrypted=%d", len(plaintext), len(decrypted))
	}
}

func TestSerializeDeserialize(t *testing.T) {
	// Generate a test KEK
	kek, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	// Create encryption service
	service, err := NewEncryptionService(kek)
	if err != nil {
		t.Fatalf("Failed to create encryption service: %v", err)
	}

	plaintext := []byte("Test serialization")
	keyVersion := testKeyVersion

	// Encrypt
	encrypted, err := service.Encrypt(plaintext, keyVersion)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Serialize
	serialized, err := SerializeEncryptedData(encrypted)
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	// Deserialize
	deserialized, err := DeserializeEncryptedData(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	// Decrypt deserialized data
	decrypted, err := service.Decrypt(deserialized)
	if err != nil {
		t.Fatalf("Failed to decrypt deserialized: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted deserialized data doesn't match original")
	}
}

func TestInvalidKEKSize(t *testing.T) {
	// Test with invalid KEK size
	invalidKEK := make([]byte, 16) // Should be 32 bytes

	_, err := NewEncryptionService(invalidKEK)
	if err == nil {
		t.Error("Expected error for invalid KEK size, got nil")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	// Generate two different KEKs
	kek1, _ := GenerateRandomKey(32)
	kek2, _ := GenerateRandomKey(32)

	// Create services with different keys
	service1, _ := NewEncryptionService(kek1)
	service2, _ := NewEncryptionService(kek2)

	plaintext := []byte("Test wrong key")
	keyVersion := testKeyVersion

	// Encrypt with first service
	encrypted, err := service1.Encrypt(plaintext, keyVersion)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Try to decrypt with second service (wrong key)
	_, err = service2.Decrypt(encrypted)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key, got nil")
	}
}
