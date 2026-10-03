package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hardware-binding guards for INV-ENCRYPTION-27 (ADR-038 tier 2): a KEK sealed by
// one TPM must not unseal on another.
//
// These run against the go-tpm-tools in-process simulator (see simOpener in
// tpm_provider_test.go), where "different hardware" means a simulator built from a
// different seed, and so a different storage-root primary. They exercise this
// provider's real seal/unseal command flow and the attributes it seals with.
//
// What they do not cover: a physical TPM. CI has no /dev/tpmrm0, so the device-open
// path (transport.OpenTPM) and a real chip's enforcement of FixedTPM/FixedParent are
// not exercised here. That enforcement is the TPM's job, per the TCG spec; this
// provider's job is to ask for it, which TestTPMSeal_ObjectIsFixedToTPMAndParent
// checks. The provider also enforces no PCR policy (see the tpm_provider.go package
// doc), so nothing here proves binding to a boot state, only to the chip.

// readSealedBlob decodes the sealed blob a provider persisted under dir.
func readSealedBlob(t *testing.T, dir string) tpmSealedBlob {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "kek.tpm"))
	require.NoError(t, err)
	var blob tpmSealedBlob
	require.NoError(t, json.Unmarshal(raw, &blob))
	return blob
}

// TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal models exfiltrating the
// sealed blob file to a second machine: the copy lands in a fresh directory and is
// opened against several other TPMs. None may unseal it, and no failed attempt may
// silently mint a replacement KEK. The same TPM still unseals the copy, which
// shows the binding is to the TPM, not to the file's path.
func TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal(t *testing.T) {
	srcDir := t.TempDir()
	const sealingSeed = 4242
	kek, err := newTPMProvider(t, srcDir, sealingSeed).KEK()
	require.NoError(t, err)

	raw, err := os.ReadFile(filepath.Join(srcDir, "kek.tpm"))
	require.NoError(t, err)

	for _, otherSeed := range []int64{1, 2, 3, 4241, 4243, 99999} {
		dstDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dstDir, "kek.tpm"), raw, 0600))

		got, err := newTPMProvider(t, dstDir, otherSeed).KEK()
		require.Error(t, err, "TPM seed %d must not unseal a blob sealed by seed %d", otherSeed, sealingSeed)
		assert.Nil(t, got, "a failed unseal must return no key material")
		assert.Contains(t, err.Error(), "unseal failed")

		after, rerr := os.ReadFile(filepath.Join(dstDir, "kek.tpm"))
		require.NoError(t, rerr)
		assert.Equal(t, raw, after, "a failed unseal must not overwrite the sealed blob (no silent re-seal under a new KEK)")
	}

	dstDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "kek.tpm"), raw, 0600))
	same, err := newTPMProvider(t, dstDir, sealingSeed).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, same, "the sealing TPM must still unseal the blob after it is moved")
}

// TestTPMBinding_DiskBlobDoesNotContainKEK checks that the only thing on disk is
// the TPM-wrapped object: the plaintext KEK appears nowhere in the persisted file.
func TestTPMBinding_DiskBlobDoesNotContainKEK(t *testing.T) {
	dir := t.TempDir()
	kek, err := newTPMProvider(t, dir, 7).KEK()
	require.NoError(t, err)
	require.Len(t, kek, KEKSize)

	raw, err := os.ReadFile(filepath.Join(dir, "kek.tpm"))
	require.NoError(t, err)
	blob := readSealedBlob(t, dir)
	for name, b := range map[string][]byte{"file": raw, "public": blob.Public, "private": blob.Private} {
		assert.False(t, bytes.Contains(b, kek), "the plaintext KEK must not appear in the sealed blob's %s bytes", name)
	}
	// The file is JSON, which encodes []byte as base64; check the common text
	// encodings of the KEK too, not only its raw bytes.
	for name, enc := range map[string]string{
		"base64":     base64.StdEncoding.EncodeToString(kek),
		"base64-raw": base64.RawStdEncoding.EncodeToString(kek),
		"hex":        hex.EncodeToString(kek),
	} {
		assert.NotContains(t, string(raw), enc, "the KEK must not appear %s-encoded in the sealed blob file", name)
	}
}

// TestTPMBinding_TamperedPrivateDoesNotUnseal flips each byte of the sealed
// private area in turn: the TPM's integrity check must reject every one, on the
// sealing TPM itself.
func TestTPMBinding_TamperedPrivateDoesNotUnseal(t *testing.T) {
	dir := t.TempDir()
	const seed = 11
	_, err := newTPMProvider(t, dir, seed).KEK()
	require.NoError(t, err)
	blob := readSealedBlob(t, dir)

	p := newTPMProvider(t, dir, seed)
	for i := range blob.Private {
		tampered := tpmSealedBlob{Public: blob.Public, Private: append([]byte(nil), blob.Private...)}
		tampered.Private[i] ^= 0xFF
		_, uerr := p.unseal(tampered)
		assert.Error(t, uerr, "flipping private byte %d must make unseal fail", i)
	}
}

// TestTPMSeal_ObjectIsFixedToTPMAndParent checks the attributes the provider asks
// the TPM to enforce. FixedTPM forbids duplicating the sealed object to another
// TPM; FixedParent forbids re-parenting it. Without them, a TPM owner could legally
// export the KEK object to different hardware, and "sealed to this TPM" would no
// longer hold even on a real chip. The persisted public area must also be the one
// the TPM returned: a keyed-hash (sealed data) object with no signing/decrypt use.
func TestTPMSeal_ObjectIsFixedToTPMAndParent(t *testing.T) {
	dir := t.TempDir()
	_, err := newTPMProvider(t, dir, 21).KEK()
	require.NoError(t, err)
	blob := readSealedBlob(t, dir)

	pub2b, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
	require.NoError(t, err)
	pub, err := pub2b.Contents()
	require.NoError(t, err)

	assert.Equal(t, tpm2.TPMAlgKeyedHash, pub.Type, "the sealed object must be a keyed-hash (sealed data) object")
	attrs := pub.ObjectAttributes
	assert.True(t, attrs.FixedTPM, "FixedTPM must be set: the sealed KEK must not be duplicable to another TPM")
	assert.True(t, attrs.FixedParent, "FixedParent must be set: the sealed KEK must not be re-parentable")
	assert.False(t, attrs.SignEncrypt, "a sealed-data object must not be usable as a signing key")
	assert.False(t, attrs.Decrypt, "a sealed-data object must not be usable as a decryption key")
}
