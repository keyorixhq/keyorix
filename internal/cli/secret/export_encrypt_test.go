package secret

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
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

// TestEncryptExport_MissingPubKeyFile verifies that encryptExport returns an
// error when the public key file does not exist.
func TestEncryptExport_MissingPubKeyFile(t *testing.T) {
	_, err := encryptExport([]byte(`{}`), filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil {
		t.Fatal("expected error for missing public key file, got nil")
	}
}

// TestEncryptExport_NoPEMBlock verifies that encryptExport returns an error
// when the file exists but contains no PEM block.
func TestEncryptExport_NoPEMBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not_pem.txt")
	if err := os.WriteFile(path, []byte("this is not a PEM file"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := encryptExport([]byte(`{}`), path)
	if err == nil {
		t.Fatal("expected error for file with no PEM block, got nil")
	}
	if !contains(err.Error(), "no PEM block") {
		t.Errorf("error %q should mention 'no PEM block'", err)
	}
}

// TestEncryptExport_InvalidPEMContent verifies that encryptExport returns an
// error when the PEM block cannot be parsed as either PKCS1 or PKIX.
func TestEncryptExport_InvalidPEMContent(t *testing.T) {
	// Write a PEM block with garbage bytes — neither PKCS1 nor PKIX can parse it.
	block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte("garbage bytes not a valid key")}
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := encryptExport([]byte(`{}`), path)
	if err == nil {
		t.Fatal("expected error for invalid PEM content, got nil")
	}
	if !contains(err.Error(), "cannot parse public key") {
		t.Errorf("error %q should mention 'cannot parse public key'", err)
	}
}

// TestEncryptExport_PKIXNonRSAKey verifies that encryptExport rejects a PKIX
// public key that is not an RSA key (e.g. ECDSA).
func TestEncryptExport_PKIXNonRSAKey(t *testing.T) {
	// Generate an ECDSA key and encode it as PKIX PEM.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "ec_pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err = encryptExport([]byte(`{}`), path)
	if err == nil {
		t.Fatal("expected error for non-RSA PKIX key, got nil")
	}
	if !contains(err.Error(), "not an RSA key") {
		t.Errorf("error %q should mention 'not an RSA key'", err)
	}
}

// TestDecryptExport_MissingPrivKeyFile verifies that decryptExport returns an
// error when the private key file does not exist.
func TestDecryptExport_MissingPrivKeyFile(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	_ = priv

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	_, err = decryptExport(envelope, filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil {
		t.Fatal("expected error for missing private key file, got nil")
	}
}

// TestDecryptExport_WrongEnvelopeFormat verifies that decryptExport returns an
// error when the envelope carries an unrecognised format string.
func TestDecryptExport_WrongEnvelopeFormat(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	// Replace the format field to simulate a foreign envelope version.
	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Format = "keyorix-encrypted-export-v99"
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = decryptExport(tampered, privPath)
	if err == nil {
		t.Fatal("expected error for wrong envelope format, got nil")
	}
	if !contains(err.Error(), "unexpected envelope format") {
		t.Errorf("error %q should mention 'unexpected envelope format'", err)
	}
}

// TestDecryptExport_NoPEMBlock verifies that decryptExport returns an error
// when the private key file exists but contains no PEM block.
func TestDecryptExport_NoPEMBlock(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	path := filepath.Join(t.TempDir(), "not_pem.txt")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = decryptExport(envelope, path)
	if err == nil {
		t.Fatal("expected error for private key file with no PEM block, got nil")
	}
	if !contains(err.Error(), "no PEM block") {
		t.Errorf("error %q should mention 'no PEM block'", err)
	}
}

// TestDecryptExport_InvalidPrivPEMContent verifies that decryptExport returns an
// error when the PEM block cannot be parsed as a private key.
func TestDecryptExport_InvalidPrivPEMContent(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("garbage")}
	path := filepath.Join(t.TempDir(), "bad_priv.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = decryptExport(envelope, path)
	if err == nil {
		t.Fatal("expected error for invalid private key PEM, got nil")
	}
	if !contains(err.Error(), "cannot parse private key") {
		t.Errorf("error %q should mention 'cannot parse private key'", err)
	}
}

// TestDecryptExport_PKCS8NonRSAKey verifies that decryptExport rejects a
// PKCS8-encoded private key that is not an RSA key (e.g. ECDSA).
func TestDecryptExport_PKCS8NonRSAKey(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	// Build a PKCS8 PEM for an ECDSA key.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "ec_priv.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = decryptExport(envelope, path)
	if err == nil {
		t.Fatal("expected error for non-RSA PKCS8 private key, got nil")
	}
	if !contains(err.Error(), "not an RSA key") {
		t.Errorf("error %q should mention 'not an RSA key'", err)
	}
}

// TestDecryptExport_BadBase64EncryptedKey verifies that decryptExport returns
// an error when the encrypted_key field is not valid base64.
func TestDecryptExport_BadBase64EncryptedKey(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.EncryptedKey = "!!!invalid base64!!!"
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = decryptExport(tampered, privPath)
	if err == nil {
		t.Fatal("expected error for bad base64 encrypted_key, got nil")
	}
	if !contains(err.Error(), "decode encrypted_key") {
		t.Errorf("error %q should mention 'decode encrypted_key'", err)
	}
}

// TestDecryptExport_BadBase64Nonce verifies that decryptExport returns an error
// when the nonce field is not valid base64.
func TestDecryptExport_BadBase64Nonce(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Nonce = "!!!bad!!!"
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = decryptExport(tampered, privPath)
	if err == nil {
		t.Fatal("expected error for bad base64 nonce, got nil")
	}
	if !contains(err.Error(), "decode nonce") {
		t.Errorf("error %q should mention 'decode nonce'", err)
	}
}

// TestDecryptExport_BadBase64Ciphertext verifies that decryptExport returns an
// error when the ciphertext field is not valid base64.
func TestDecryptExport_BadBase64Ciphertext(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Ciphertext = "!!!bad!!!"
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = decryptExport(tampered, privPath)
	if err == nil {
		t.Fatal("expected error for bad base64 ciphertext, got nil")
	}
	if !contains(err.Error(), "decode ciphertext") {
		t.Errorf("error %q should mention 'decode ciphertext'", err)
	}
}

// TestDecryptExport_BadJSON verifies that decryptExport returns an error when
// the envelope bytes are not valid JSON.
func TestDecryptExport_BadJSON(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	privPath := writePKCS1PrivKey(t, priv)
	_, err := decryptExport([]byte("not json at all"), privPath)
	if err == nil {
		t.Fatal("expected error for non-JSON envelope, got nil")
	}
	if !contains(err.Error(), "parse encrypted envelope") {
		t.Errorf("error %q should mention 'parse encrypted envelope'", err)
	}
}

// TestDecryptExport_GCMAuthFailure verifies that decryptExport returns a GCM
// authentication error when the ciphertext bytes are corrupted (but the base64
// encoding itself is still valid). This specifically covers the gcm.Open error
// path in decryptExport.
func TestDecryptExport_GCMAuthFailure(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	envelope, err := encryptExport([]byte(`{"KEY":"value"}`), pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}

	// Unmarshal the envelope, flip a byte in the DECODED ciphertext bytes,
	// then re-base64-encode so the base64 decode step succeeds but GCM
	// authentication detects the tampering.
	var env encryptedExportEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ctBytes, err := b64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	// Flip a byte at the start of the ciphertext payload.
	if len(ctBytes) > 0 {
		ctBytes[0] ^= 0xff
	}
	env.Ciphertext = b64.StdEncoding.EncodeToString(ctBytes)

	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = decryptExport(tampered, privPath)
	if err == nil {
		t.Fatal("expected GCM authentication error for corrupted ciphertext bytes, got nil")
	}
	if !contains(err.Error(), "AES-GCM decrypt") {
		t.Errorf("error %q should mention 'AES-GCM decrypt'", err)
	}
}

// contains is a small helper to avoid importing strings in test assertions.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
