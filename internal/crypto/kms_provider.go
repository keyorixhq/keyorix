package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// KMSClient is the minimal envelope-encryption surface a cloud KMS exposes: wrap
// (Encrypt) and unwrap (Decrypt) a small blob with a key that never leaves the
// KMS/HSM. Keeping it an interface keeps this package free of any cloud SDK — the
// AWS / GCP / Azure implementations live in subpackages, and tests use a fake.
// ciphertext is opaque, provider-specific KMS output.
type KMSClient interface {
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, err error)
}

// kmsCallTimeout bounds a single KMS round-trip at startup.
const kmsCallTimeout = 30 * time.Second

// KMSKeyProvider sources the KEK via cloud-KMS envelope encryption (ADR-041): a
// random 32-byte KEK is wrapped by the KMS key and the *wrapped* blob is stored on
// disk; at startup the KMS unwraps it into memory. The KMS key (CMK) never leaves
// the KMS, and the on-disk blob is ciphertext. First run generates and wraps the
// KEK; subsequent runs decrypt the stored blob.
type KMSKeyProvider struct {
	client         KMSClient
	baseDir        string
	wrappedKeyPath string
	name           string
}

// NewKMSKeyProvider builds a KMS-backed provider. name identifies the backend
// (e.g. "aws-kms") for logging/metadata; wrappedKeyPath is resolved under baseDir.
func NewKMSKeyProvider(client KMSClient, name, baseDir, wrappedKeyPath string) *KMSKeyProvider {
	return &KMSKeyProvider{client: client, name: name, baseDir: baseDir, wrappedKeyPath: wrappedKeyPath}
}

func (p *KMSKeyProvider) Name() string { return p.name }

func (p *KMSKeyProvider) KEK() ([]byte, error) {
	if p.client == nil {
		return nil, fmt.Errorf("%s key provider: no KMS client configured", p.name)
	}
	if p.wrappedKeyPath == "" {
		return nil, fmt.Errorf("%s key provider: wrapped_key_path is required", p.name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), kmsCallTimeout)
	defer cancel()

	full := filepath.Join(p.baseDir, p.wrappedKeyPath)
	if _, err := os.Stat(full); os.IsNotExist(err) {
		return p.generateAndWrap(ctx)
	}
	wrapped, err := securefiles.SafeReadFile(p.baseDir, p.wrappedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%s key provider: read wrapped KEK: %w", p.name, err)
	}
	kek, err := p.client.Decrypt(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("%s key provider: KMS decrypt failed: %w", p.name, err)
	}
	return validateKEK(kek, p.name)
}

// generateAndWrap creates a fresh KEK, wraps it with the KMS key, persists the
// wrapped blob (0600), and returns the plaintext KEK. First-run only.
func (p *KMSKeyProvider) generateAndWrap(ctx context.Context) ([]byte, error) {
	kek := make([]byte, KEKSize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("%s key provider: generate KEK: %w", p.name, err)
	}
	wrapped, err := p.client.Encrypt(ctx, kek)
	if err != nil {
		return nil, fmt.Errorf("%s key provider: KMS encrypt failed: %w", p.name, err)
	}
	if err := securefiles.SecureWriteFile(p.baseDir, p.wrappedKeyPath, wrapped, 0600); err != nil {
		return nil, fmt.Errorf("%s key provider: persist wrapped KEK: %w", p.name, err)
	}
	return kek, nil
}
