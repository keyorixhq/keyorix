package secret

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// generateTestKeyPair returns a fresh 2048-bit RSA key pair.
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv, &priv.PublicKey
}

// writePKCS1PubKey writes an RSA public key in PKCS1 PEM format to a temp file
// and returns its path.
func writePKCS1PubKey(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PublicKey(pub)
	block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}
	return path
}

// writePKIXPubKey writes an RSA public key in PKIX (SubjectPublicKeyInfo) PEM
// format to a temp file and returns its path.
func writePKIXPubKey(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "pub_pkix.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write pkix pub key: %v", err)
	}
	return path
}

// writePKCS1PrivKey writes an RSA private key in PKCS1 PEM format to a temp
// file and returns its path.
func writePKCS1PrivKey(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "priv.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write priv key: %v", err)
	}
	return path
}

// writePKCS8PrivKey writes an RSA private key in PKCS8 PEM format to a temp
// file and returns its path.
func writePKCS8PrivKey(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "priv_pkcs8.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write pkcs8 priv key: %v", err)
	}
	return path
}

// TestEncryptDecryptRoundTrip verifies that a message encrypted with a public
// key can be decrypted with the corresponding private key.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	plaintext := []byte(`{"DB_PASSWORD":"supersecret","API_KEY":"sk_live_abc123"}`)

	envelope, err := encryptExport(plaintext, pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	got, err := decryptExport(envelope, privPath)
	if err != nil {
		t.Fatalf("decryptExport: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", plaintext, got)
	}
}

// TestEncryptExport_WrongKey verifies that decryption with a different private
// key fails.
func TestEncryptExport_WrongKey(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	wrongPriv, _ := generateTestKeyPair(t)

	pubPath := writePKCS1PubKey(t, pub)
	wrongPrivPath := writePKCS1PrivKey(t, wrongPriv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	_, err = decryptExport(envelope, wrongPrivPath)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong private key, got nil")
	}
}

// TestEncryptExport_TamperedCiphertext verifies that GCM authentication catches
// a tampered ciphertext.
func TestEncryptExport_TamperedCiphertext(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	// Parse the envelope, flip a byte in Ciphertext, re-encode.
	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	// Corrupt the last base64 character if it's not a padding '='.
	ct := []byte(env.Ciphertext)
	for i := len(ct) - 1; i >= 0; i-- {
		if ct[i] != '=' {
			ct[i] ^= 0xff
			break
		}
	}
	env.Ciphertext = string(ct)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}

	_, err = decryptExport(tampered, privPath)
	if err == nil {
		t.Fatal("expected GCM authentication error for tampered ciphertext, got nil")
	}
}

// TestDecryptExport_PKCS8Key verifies that a PKCS8-encoded private key works.
func TestDecryptExport_PKCS8Key(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS8PrivKey(t, priv)

	plaintext := []byte(`{"SECRET":"pkcs8-works"}`)

	envelope, err := encryptExport(plaintext, pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	got, err := decryptExport(envelope, privPath)
	if err != nil {
		t.Fatalf("decryptExport with PKCS8 key: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("PKCS8 round-trip mismatch:\n  want: %s\n  got:  %s", plaintext, got)
	}
}

// TestDecryptExport_PKIXPublicKey verifies that a PKIX (SubjectPublicKeyInfo)
// encoded public key works for encryption.
func TestDecryptExport_PKIXPublicKey(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKIXPubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	plaintext := []byte(`{"SECRET":"pkix-pub-works"}`)

	envelope, err := encryptExport(plaintext, pubPath)
	if err != nil {
		t.Fatalf("encryptExport with PKIX public key: %v", err)
	}

	got, err := decryptExport(envelope, privPath)
	if err != nil {
		t.Fatalf("decryptExport: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("PKIX round-trip mismatch:\n  want: %s\n  got:  %s", plaintext, got)
	}
}

// TestEncryptedExportFormat verifies that the envelope JSON has the expected
// top-level fields and correct constant values.
func TestEncryptedExportFormat(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	envelopeBytes, err := encryptExport([]byte(`{"KEY":"val"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	if env.Format != encryptedExportFormat {
		t.Errorf("Format = %q, want %q", env.Format, encryptedExportFormat)
	}
	if env.Algorithm != encryptedExportAlgorithm {
		t.Errorf("Algorithm = %q, want %q", env.Algorithm, encryptedExportAlgorithm)
	}
	if env.EncryptedKey == "" {
		t.Error("EncryptedKey is empty")
	}
	if env.Nonce == "" {
		t.Error("Nonce is empty")
	}
	if env.Ciphertext == "" {
		t.Error("Ciphertext is empty")
	}
}
