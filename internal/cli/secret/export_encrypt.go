package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// encryptedExportEnvelope is the JSON shape of an encrypted export file.
type encryptedExportEnvelope struct {
	Format       string `json:"format"`
	Algorithm    string `json:"algorithm"`
	EncryptedKey string `json:"encrypted_key"` // base64(RSA-OAEP-SHA256(aesKey))
	Nonce        string `json:"nonce"`          // base64(12-byte nonce)
	Ciphertext   string `json:"ciphertext"`     // base64(AES-256-GCM(payload))
}

const (
	encryptedExportFormat    = "keyorix-encrypted-export-v1"
	encryptedExportAlgorithm = "RSA-OAEP-SHA256+AES-256-GCM"
)

// encryptExport encrypts plainJSON bytes with the RSA public key at pubKeyPath.
// Returns the JSON-encoded encryptedExportEnvelope bytes.
func encryptExport(plainJSON []byte, pubKeyPath string) ([]byte, error) {
	// 1. Load PEM public key
	pemBytes, err := os.ReadFile(pubKeyPath) // #nosec G304 — operator-supplied CLI path
	if err != nil {
		return nil, fmt.Errorf("read public key %q: %w", pubKeyPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", pubKeyPath)
	}

	// Try PKCS1 first, then PKIX (SubjectPublicKeyInfo).
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		key, err2 := x509.ParsePKIXPublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("cannot parse public key (tried PKCS1: %v; PKIX: %v)", err, err2)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key in %q is not an RSA key", pubKeyPath)
		}
		pub = rsaKey
	}

	// 2. Generate random 32-byte AES key.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}

	// 3. RSA-OAEP-SHA256 encrypt the AES key.
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt AES key: %w", err)
	}

	// 4. AES-256-GCM encrypt the payload.
	block2, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plainJSON, nil)

	// 5. Build envelope.
	env := encryptedExportEnvelope{
		Format:       encryptedExportFormat,
		Algorithm:    encryptedExportAlgorithm,
		EncryptedKey: base64.StdEncoding.EncodeToString(encKey),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(env, "", "  ")
}

// decryptExport reverses encryptExport, returning the plaintext JSON bytes.
func decryptExport(envelopeBytes []byte, privKeyPath string) ([]byte, error) {
	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		return nil, fmt.Errorf("parse encrypted envelope: %w", err)
	}
	if env.Format != encryptedExportFormat {
		return nil, fmt.Errorf("unexpected envelope format %q (want %q)", env.Format, encryptedExportFormat)
	}

	// Load private key (try PKCS1 then PKCS8).
	pemBytes, err := os.ReadFile(privKeyPath) // #nosec G304 — operator-supplied CLI path
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", privKeyPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", privKeyPath)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("cannot parse private key (tried PKCS1: %v; PKCS8: %v)", err, err2)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key in %q is not an RSA key", privKeyPath)
		}
		priv = rsaKey
	}

	encKey, err := base64.StdEncoding.DecodeString(env.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted_key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertextBytes, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decrypt AES key: %w", err)
	}

	block2, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt: %w", err)
	}
	return plain, nil
}
