package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
)

// #4278: `secret export --encrypt-for` writes a pretty-printed envelope; `secret import
// --decrypt-with` used to look for a compact `{"format":"` byte prefix, never matched it,
// and parsed the envelope itself as a flat JSON secret file (importing "algorithm",
// "ciphertext", ... as secrets).

type envelopeKeys struct{ pub, priv, otherPriv string }

func writeEnvelopeKeys(t *testing.T) envelopeKeys {
	t.Helper()
	dir := t.TempDir()
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelopeKeys{
		pub:       write("pub.pem", "PUBLIC KEY", pubDER),
		priv:      write("priv.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
		otherPriv: write("other.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(other)),
	}
}

// exportEncrypted produces the file `secret export --encrypt-for` writes for n secrets.
func exportEncrypted(t *testing.T, pubKey string, n int) string {
	t.Helper()
	secrets := make([]exportedSecret, n)
	for i := range secrets {
		secrets[i] = exportedSecret{ID: i + 1, Name: fmt.Sprintf("SECRET_%d", i+1), Value: fmt.Sprintf("value-%d", i+1)}
	}
	var buf bytes.Buffer
	if err := writeEncryptedJSON(&buf, secrets, pubKey); err != nil {
		t.Fatalf("writeEncryptedJSON: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("\n  \"format\"")) {
		t.Fatalf("test premise: the export is expected to be pretty-printed, got %q", buf.String())
	}
	p := filepath.Join(t.TempDir(), "secrets.enc.json")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setImportFlags(t *testing.T, file, format, decryptWith string) {
	t.Helper()
	setStr(t, &importFile, file)
	setStr(t, &importFormat, format)
	setStr(t, &importDecryptWith, decryptWith)
	oldP, oldE, oldD := importProject, importEnv, importDryRun
	importProject, importEnv, importDryRun = 1, 1, false
	t.Cleanup(func() { importProject, importEnv, importDryRun = oldP, oldE, oldD })
}

func TestSecretImport_EncryptedExportRoundTripsNineSecrets(t *testing.T) {
	keys := writeEnvelopeKeys(t)
	file := exportEncrypted(t, keys.pub, 9)

	for _, format := range []string{"dotenv", "json"} {
		t.Run("format="+format, func(t *testing.T) {
			var created atomic.Int32
			names := map[string]bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				created.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprint(w, `{"data":{"ID":1}}`)
			}))
			defer srv.Close()
			setPATCreds(t, srv)
			setImportFlags(t, file, format, keys.priv)

			entries, err := collectImportEntries()
			if err != nil {
				t.Fatalf("collectImportEntries: %v", err)
			}
			for _, e := range entries {
				names[e.Name] = true
			}
			if len(entries) != 9 {
				t.Fatalf("got %d entries, want 9: %v", len(entries), names)
			}
			for i := 1; i <= 9; i++ {
				if !names[fmt.Sprintf("SECRET_%d", i)] {
					t.Errorf("SECRET_%d missing from %v", i, names)
				}
			}
			for _, junk := range []string{"algorithm", "encrypted_key", "nonce", "ciphertext", "format"} {
				if names[junk] {
					t.Errorf("envelope field %q was imported as a secret", junk)
				}
			}

			_, _ = captureStdoutAndStderr(t, func() {
				if err := runSecretImport(&cobra.Command{}, nil); err != nil {
					t.Fatalf("runSecretImport: %v", err)
				}
			})
			if got := created.Load(); got != 9 {
				t.Fatalf("server saw %d creates, want 9", got)
			}
		})
	}
}

func TestSecretImport_EncryptedExportWithWrongKeyImportsNothing(t *testing.T) {
	keys := writeEnvelopeKeys(t)
	file := exportEncrypted(t, keys.pub, 9)

	var created atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		created.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	setImportFlags(t, file, "json", keys.otherPriv)

	var err error
	_, _ = captureStdoutAndStderr(t, func() { err = runSecretImport(&cobra.Command{}, nil) })
	if err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("err = %v, want a decrypt refusal", err)
	}
	if got := created.Load(); got != 0 {
		t.Fatalf("a wrong key must not import anything; server saw %d creates", got)
	}
}

// An envelope with no --decrypt-with must be refused with what to do, whatever --format
// says: its fields are never secrets.
func TestSecretImport_EncryptedExportWithoutDecryptWithIsRefused(t *testing.T) {
	keys := writeEnvelopeKeys(t)
	file := exportEncrypted(t, keys.pub, 3)

	for _, format := range []string{"json", "dotenv", "vault"} {
		t.Run("format="+format, func(t *testing.T) {
			setImportFlags(t, file, format, "")
			entries, err := collectImportEntries()
			if err == nil {
				t.Fatalf("envelope accepted without --decrypt-with, entries: %v", entries)
			}
			if !containsAll(err.Error(), "--decrypt-with", "encrypted") {
				t.Fatalf("err = %q, want it to say the file is encrypted and to name --decrypt-with", err)
			}
		})
	}
}

// A plain JSON file that merely has a "format" key is not an envelope.
func TestSecretImport_PlainJSONWithFormatKeyIsStillImported(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.json")
	if err := os.WriteFile(p, []byte("{\n  \"format\": \"pdf\",\n  \"TOKEN\": \"x\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := writeEnvelopeKeys(t)
	for _, decryptWith := range []string{"", keys.priv} {
		setImportFlags(t, p, "json", decryptWith)
		entries, err := collectImportEntries()
		if err != nil || len(entries) != 2 {
			t.Fatalf("decryptWith=%q: entries=%v err=%v, want 2 plain entries", decryptWith, entries, err)
		}
	}
}
