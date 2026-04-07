package encryption

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Service provides high-level encryption operations for the application
type Service struct {
	keyManager        *KeyManager
	encryptionService *EncryptionService
	config            *config.EncryptionConfig
	mu                sync.RWMutex
	initialized       bool
}

// NewService creates a new encryption service
func NewService(cfg *config.EncryptionConfig, baseDir string) *Service {
	return &Service{
		config: cfg,
		keyManager: NewKeyManager(
			baseDir,
			cfg.KEKPath,
			cfg.DEKPath,
		),
	}
}

// Initialize sets up the encryption service
func (s *Service) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	// Initialize key manager
	if err := s.keyManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}

	// Create encryption service with KEK
	kek := s.keyManager.GetKEK()
	encSvc, err := NewEncryptionService(kek)
	if err != nil {
		return fmt.Errorf("failed to create encryption service: %w", err)
	}
	s.encryptionService = encSvc

	s.initialized = true
	return nil
}

// IsEnabled returns whether encryption is enabled
func (s *Service) IsEnabled() bool {
	return s.config.Enabled
}

// IsInitialized returns whether the service is initialized
func (s *Service) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

// EncryptSecret encrypts a secret value and returns encrypted data with metadata
func (s *Service) EncryptSecret(plaintext []byte) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}

	keyVersion := s.keyManager.GetKeyVersion()
	encrypted, err := s.encryptionService.Encrypt(plaintext, keyVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Serialize encrypted data
	encryptedBytes, err := SerializeEncryptedData(encrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize encrypted data: %w", err)
	}

	// Serialize metadata
	metadataBytes, err := json.Marshal(encrypted.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}

	return encryptedBytes, metadataBytes, nil
}

// DecryptSecret decrypts a secret value from encrypted data
func (s *Service) DecryptSecret(encryptedData []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}

	// Deserialize encrypted data
	encrypted, err := DeserializeEncryptedData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}

	// Decrypt
	plaintext, err := s.encryptionService.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return plaintext, nil
}

// EncryptLargeSecret encrypts large secrets using chunking
func (s *Service) EncryptLargeSecret(plaintext []byte, chunkSizeKB int) ([][]byte, [][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}

	chunkSize := chunkSizeKB * 1024
	keyVersion := s.keyManager.GetKeyVersion()

	chunks, err := s.encryptionService.EncryptChunked(plaintext, chunkSize, keyVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt chunked secret: %w", err)
	}

	var encryptedChunks [][]byte
	var metadataChunks [][]byte

	for i, chunk := range chunks {
		// Serialize encrypted chunk
		encryptedBytes, err := SerializeEncryptedData(chunk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize chunk %d: %w", i, err)
		}
		encryptedChunks = append(encryptedChunks, encryptedBytes)

		// Serialize metadata
		metadataBytes, err := json.Marshal(chunk.Metadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize metadata for chunk %d: %w", i, err)
		}
		metadataChunks = append(metadataChunks, metadataBytes)
	}

	return encryptedChunks, metadataChunks, nil
}

// DecryptLargeSecret decrypts large secrets from chunks
func (s *Service) DecryptLargeSecret(encryptedChunks [][]byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}

	var chunks []*EncryptedData
	for i, encryptedChunk := range encryptedChunks {
		chunk, err := DeserializeEncryptedData(encryptedChunk)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize chunk %d: %w", i, err)
		}
		chunks = append(chunks, chunk)
	}

	plaintext, err := s.encryptionService.DecryptChunked(chunks)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt chunked secret: %w", err)
	}

	return plaintext, nil
}

// RotateKeys rotates encryption keys
func (s *Service) RotateKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return fmt.Errorf("encryption service not initialized")
	}

	// Rotate KEK
	if err := s.keyManager.RotateKEK(); err != nil {
		return fmt.Errorf("failed to rotate KEK: %w", err)
	}

	// Recreate encryption service with new KEK
	kek := s.keyManager.GetKEK()
	encSvc, err := NewEncryptionService(kek)
	if err != nil {
		return fmt.Errorf("failed to recreate encryption service: %w", err)
	}
	s.encryptionService = encSvc

	return nil
}

// ValidateKeyFiles validates encryption key files
func (s *Service) ValidateKeyFiles() error {
	return s.keyManager.ValidateKeyFiles()
}

// FixKeyFilePermissions fixes key file permissions
func (s *Service) FixKeyFilePermissions() error {
	return s.keyManager.FixKeyFilePermissions()
}

// GetKeyVersion returns the current key version
func (s *Service) GetKeyVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return "unknown"
	}

	return s.keyManager.GetKeyVersion()
}

// Shutdown cleanly shuts down the encryption service
func (s *Service) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.keyManager != nil {
		s.keyManager.Wipe()
	}

	s.initialized = false
}
