// evidence_roundtrip_test.go — red/green coverage for inventory §6 GAP-2 /
// Finding S16: `compliance export` followed by `compliance verify` on the
// exact same, untampered pack must return VALID. Before the fix, export
// never signed anything or learned a canonical filename, and verify's
// request never carried a filename at all (though the server's
// VerifyComplianceEvidence has required one since AUD-009) — so the
// documented workflow could never produce VALID, and there was no way to
// distinguish an untampered pack from a tampered one either.
//
// fakeEvidenceServer below reimplements just enough of the real HMAC
// (core.KeyorixCore.signEvidence / VerifyEvidenceSignature) to exercise the
// CLI's request/response wiring without depending on internal/core from a
// _test.go in this package.
package compliance

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testEvidenceSignKey     = "0123456789abcdef0123456789abcdef"
	testEvidenceKeyVersion  = "v1"
	testEvidenceCanonicalFN = "keyorix-evidence-20260923T120000Z.json"
)

// signTestEvidence reproduces core.KeyorixCore.signEvidence exactly (HMAC-SHA256
// over filename, a null separator, then data) so this fake server produces
// signatures the CLI's real request/response plumbing can round-trip.
func signTestEvidence(filename string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(testEvidenceSignKey))
	mac.Write([]byte(filename))
	mac.Write([]byte{0})
	mac.Write(data)
	return testEvidenceKeyVersion + ":" + hex.EncodeToString(mac.Sum(nil))
}

// fakeEvidenceServer mimics GET /api/v1/compliance/evidence (export) and
// POST /api/v1/compliance/evidence/verify, signing/verifying with the exact
// algorithm internal/core uses.
func fakeEvidenceServer(t *testing.T) http.HandlerFunc {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/compliance/evidence", func(w http.ResponseWriter, r *http.Request) {
		data, err := json.MarshalIndent(map[string]interface{}{
			"generated_at": "2026-09-23T12:00:00Z",
			"posture":      map[string]interface{}{"ok": true},
		}, "", "  ")
		require.NoError(t, err)
		sig := signTestEvidence(testEvidenceCanonicalFN, data)
		resp, err := json.Marshal(map[string]interface{}{
			"data": map[string]interface{}{
				"filename":  testEvidenceCanonicalFN,
				"data_b64":  base64.StdEncoding.EncodeToString(data),
				"signature": sig,
				"signed":    true,
			},
		})
		require.NoError(t, err)
		_, _ = w.Write(resp)
	})
	mux.HandleFunc("/api/v1/compliance/evidence/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DataB64   string `json:"data_b64"`
			Signature string `json:"signature"`
			Filename  string `json:"filename"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		data, err := base64.StdEncoding.DecodeString(body.DataB64)
		require.NoError(t, err)
		want := signTestEvidence(body.Filename, data)
		valid := hmac.Equal([]byte(want), []byte(body.Signature))
		reason := ""
		if !valid {
			reason = "signature does not match — the pack was modified, signed by a different deployment, or presented under the wrong filename"
		}
		resp, err := json.Marshal(map[string]interface{}{
			"data": map[string]interface{}{
				"valid":       valid,
				"key_version": testEvidenceKeyVersion,
				"reason":      reason,
			},
		})
		require.NoError(t, err)
		_, _ = w.Write(resp)
	})
	return mux.ServeHTTP
}

func resetExportVerifyFlags(t *testing.T) (packPath string) {
	t.Helper()
	dir := t.TempDir()
	// Deliberately NOT the canonical server-assigned name, to prove verify
	// doesn't depend on the local disk basename matching it.
	packPath = filepath.Join(dir, "my-evidence-pack.json")
	exportOutput, exportForce = packPath, false
	verifyFile, verifySig = packPath, ""
	t.Cleanup(func() {
		exportOutput, exportForce = "", false
		verifyFile, verifySig = "", ""
	})
	return packPath
}

// TestExportThenVerify_UntamperedPack_IsValid is the red/green case: export
// then verify the exact same pack must return VALID.
func TestExportThenVerify_UntamperedPack_IsValid(t *testing.T) {
	setupRemote(t, fakeEvidenceServer(t))
	packPath := resetExportVerifyFlags(t)

	require.NoError(t, exportCmd.RunE(nil, nil))
	_, err := os.Stat(packPath)
	require.NoError(t, err, "pack file must exist")
	_, err = os.Stat(packPath + ".sig")
	require.NoError(t, err, "detached signature must exist")

	out := captureStdout(t, func() { require.NoError(t, verifyCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "VALID")
	assert.NotContains(t, out, "NOT VERIFIED")
}

// TestExportThenVerify_TamperedContent_IsInvalid flips a byte in the
// exported pack's content; verify must fail.
func TestExportThenVerify_TamperedContent_IsInvalid(t *testing.T) {
	setupRemote(t, fakeEvidenceServer(t))
	packPath := resetExportVerifyFlags(t)
	require.NoError(t, exportCmd.RunE(nil, nil))

	data, err := os.ReadFile(packPath)
	require.NoError(t, err)
	tampered := append([]byte{}, data...)
	tampered[len(tampered)-2] ^= 0xFF // flip a byte near the end, inside the JSON body
	require.NoError(t, os.WriteFile(packPath, tampered, 0o600))

	err = verifyCmd.RunE(nil, nil)
	require.Error(t, err)
}

// TestExportThenVerify_TamperedFilename_IsInvalid edits the canonical
// filename recorded in the .sig file (line 1) without touching the pack
// content or the signature itself; verify must fail — this is exactly the
// AUD-009 substitution the filename binding exists to catch: valid
// (data, signature) presented under a different claimed identity.
func TestExportThenVerify_TamperedFilename_IsInvalid(t *testing.T) {
	setupRemote(t, fakeEvidenceServer(t))
	packPath := resetExportVerifyFlags(t)
	require.NoError(t, exportCmd.RunE(nil, nil))

	sigPath := packPath + ".sig"
	sig, err := os.ReadFile(sigPath)
	require.NoError(t, err)
	filename, signature := parseEvidenceSignatureFile(sig, packPath)
	require.Equal(t, testEvidenceCanonicalFN, filename)
	tampered := "keyorix-evidence-99999999T999999Z.json\n" + signature + "\n"
	require.NoError(t, os.WriteFile(sigPath, []byte(tampered), 0o600))

	err = verifyCmd.RunE(nil, nil)
	require.Error(t, err)
}

// TestExportThenVerify_TamperedSignature_IsInvalid flips hex digits in the
// recorded signature; verify must fail.
func TestExportThenVerify_TamperedSignature_IsInvalid(t *testing.T) {
	setupRemote(t, fakeEvidenceServer(t))
	packPath := resetExportVerifyFlags(t)
	require.NoError(t, exportCmd.RunE(nil, nil))

	sigPath := packPath + ".sig"
	sig, err := os.ReadFile(sigPath)
	require.NoError(t, err)
	filename, signature := parseEvidenceSignatureFile(sig, packPath)
	tampered := filename + "\n" + signature + "deadbeef\n"
	require.NoError(t, os.WriteFile(sigPath, []byte(tampered), 0o600))

	err = verifyCmd.RunE(nil, nil)
	require.Error(t, err)
}
