// service.go — Service struct, constructor, and encrypt/decrypt operations.
//
// For rotation, key validation, and shutdown see service_rotation.go.
package encryption

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Service provides high-level encryption operations for the application.
type Service struct {
	keyManager        *KeyManager
	encryptionService *EncryptionService
	config            *config.EncryptionConfig
	mu                sync.RWMutex
	initialized       bool
}

// NewService creates a new encryption Service.
func NewService(cfg *config.EncryptionConfig, baseDir string) *Service {
	if !cfg.Enabled {
		log.New(os.Stderr, "", 0).Println(`
╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  WARNING: ENCRYPTION IS DISABLED                             ║
║                                                                  ║
║  All secrets and tokens will be stored as PLAINTEXT.             ║
║  This is only acceptable in local development environments.      ║
║  NEVER run with encryption disabled in production.               ║
╚══════════════════════════════════════════════════════════════════╝`)
	}
	return &Service{
		config:     cfg,
		keyManager: NewKeyManager(baseDir, cfg.KEKPath, cfg.DEKPath, cfg.SaltPath),
	}
}

// Initialize sets up the encryption service.
// passphrase is used to derive the KEK via PBKDF2 — never stored.
func (s *Service) Initialize(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if err := s.keyManager.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	dek := s.keyManager.GetDEK()
	encSvc, err := NewEncryptionService(dek)
	if err != nil {
		return fmt.Errorf("failed to create encryption service: %w", err)
	}
	s.encryptionService = encSvc
	s.initialized = true
	return nil
}

// IsEnabled returns whether encryption is enabled in config.
func (s *Service) IsEnabled() bool {
	return s.config.Enabled
}

// IsInitialized returns whether the service has been initialised.
func (s *Service) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

// EncryptSecret encrypts plaintext and returns (encryptedBytes, metadataBytes, error).
func (s *Service) EncryptSecret(plaintext []byte) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := s.encryptionService.Encrypt(plaintext, s.keyManager.GetKeyVersion())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}
	encBytes, err := SerializeEncryptedData(encrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize encrypted data: %w", err)
	}
	metaBytes, err := json.Marshal(encrypted.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}
	return encBytes, metaBytes, nil
}

// EncryptSecretWithAAD encrypts plaintext bound to the given AAD.
// Use SecretAAD(secretID, namespaceID, versionNumber) to construct the AAD.
func (s *Service) EncryptSecretWithAAD(plaintext []byte, aad []byte) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := s.encryptionService.EncryptWithAAD(plaintext, s.keyManager.GetKeyVersion(), aad)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret with AAD: %w", err)
	}
	encBytes, err := SerializeEncryptedData(encrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize encrypted data: %w", err)
	}
	metaBytes, err := json.Marshal(encrypted.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}
	return encBytes, metaBytes, nil
}

// DecryptSecret decrypts a secret from encryptedData bytes.
func (s *Service) DecryptSecret(encryptedData []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := DeserializeEncryptedData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	return s.encryptionService.Decrypt(encrypted)
}

// DecryptSecretWithAAD decrypts a secret, using AAD for v1 rows and falling
// back to legacy nil-AAD for rows encrypted before the AAD migration.
// Logs a warning on the legacy path — schedule re-encryption in the M2 sweep.
func (s *Service) DecryptSecretWithAAD(encryptedData []byte, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := DeserializeEncryptedData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	if encrypted.Metadata.AADVersion != "" {
		return s.encryptionService.DecryptWithAAD(encrypted, aad)
	}
	log.Printf("[WARN] decrypting legacy secret row without AAD — schedule re-encryption in M2 migration")
	return s.encryptionService.Decrypt(encrypted)
}

// EncryptLargeSecret encrypts large secrets using chunking.
func (s *Service) EncryptLargeSecret(plaintext []byte, chunkSizeKB int) ([][]byte, [][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}
	chunks, err := s.encryptionService.EncryptChunked(plaintext, chunkSizeKB*1024, s.keyManager.GetKeyVersion())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt chunked secret: %w", err)
	}
	var encChunks, metaChunks [][]byte
	for i, chunk := range chunks {
		eb, err := SerializeEncryptedData(chunk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize chunk %d: %w", i, err)
		}
		mb, err := json.Marshal(chunk.Metadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize metadata for chunk %d: %w", i, err)
		}
		encChunks = append(encChunks, eb)
		metaChunks = append(metaChunks, mb)
	}
	return encChunks, metaChunks, nil
}

// DecryptLargeSecret decrypts a chunked large secret.
func (s *Service) DecryptLargeSecret(encryptedChunks [][]byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}
	var chunks []*EncryptedData
	for i, ec := range encryptedChunks {
		c, err := DeserializeEncryptedData(ec)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize chunk %d: %w", i, err)
		}
		chunks = append(chunks, c)
	}
	return s.encryptionService.DecryptChunked(chunks)
}
