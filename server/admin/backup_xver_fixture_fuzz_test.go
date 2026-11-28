// backup_xver_fixture_fuzz_test.go: a CROSS-VERSION restore round-trip harness.
//
// WHY this exists (RESTORE-XVER-1): every existing backup/restore fuzzer here
// writes the archive it later reads with the CURRENT code
// (FuzzBackupRestoreRoundTrip) or reads a real old-binary archive whose
// plaintexts are unknown (FuzzI6OldArchiveMutation, TestI6RestoreOldVersion). A
// reader regression that corrupted or silently dropped a secret while restoring a
// FROZEN archive -- the exact shape a customer hits when they upgrade and then
// restore a pre-upgrade backup during an incident -- would pass all of them,
// because none ties a frozen archive to a recorded canary plaintext.
//
// This target restores a FROZEN v2 archive whose canary plaintexts and metadata
// are recorded alongside it (testdata/xver/) and asserts four oracles:
//
//	O1  every recorded secret version decrypts to its exact recorded plaintext
//	    (oracleDecrypt, this package's own decrypt oracle) AND project/role/secret
//	    metadata round-trips.
//	O2  a mutated archive (truncate, bit-flip, trailing/oversize bytes, ...) either
//	    restores with O1 intact for whatever survived, OR is REFUSED with an explicit
//	    error AND leaves the target store with no half-restored rows (restore is
//	    journaled + atomically committed: restore_commit.go, internal/restorejournal).
//	O3  hostile length fields are bounded: tiny --max-entry/--max-total caps refuse
//	    promptly, the reader never buffers the whole oversized payload (resguard).
//	O4  no canary plaintext and no key-file byte ever appears in restore error/stdout.
//
// FIXTURE PROVENANCE. The frozen archive is written by the REAL current writer
// (`admin backup` via runAdminBackup over a deterministically seeded source), then
// committed byte-for-byte. Provenance = real writer, current version; it proves the
// CURRENT v2 format reads back losslessly from frozen bytes -- NOT that an N-1/N-2
// *binary*'s output does (that is TestI6RestoreOldVersion / scripts/release-qa's
// job, neither of which records plaintext). Regenerate it with
// `KEYORIX_GEN_XVER_FIXTURE=1 go test -run TestXverGenerateFixture ./server/admin/`.
// Canary plaintexts (plaintext-*) and the test passphrase are throwaway; committing
// them is intentional and carries no real key material.
//
// What this harness does NOT verify:
//   - PostgreSQL: SQLite only (no KEYORIX_TEST_PG_DSN wiring here); the metamorphic
//     fuzzer covers the PG restore path when a DSN is present.
//   - Real old *binary* output (see provenance above) and the v1 physical format
//     (readBackupArchive, covered by FuzzReadBackupArchive / TestAdminRestore_V0953Archive).
//   - The manifest HMAC signature gate's refuse path in isolation (manifest_sign_fuzz_test.go).
//   - Anything about on-disk physical layout beyond "no half-restored rows."
package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	xverFixtureDir = "testdata/xver"
	xverV2Archive  = "v2-current.tar.gz"
	xverV2Expected = "v2-current.expected.json"
)

// xverExpected is what testdata/xver/v2-current.expected.json records next to the
// frozen archive: the recorded canary plaintexts (O1), the store metadata that must
// round-trip (O1), and the throwaway key-file bytes that must never leak (O4).
type xverExpected struct {
	Format       string             `json:"format"`
	Passphrase   string             `json:"passphrase"`
	Versions     []xverKnownVersion `json:"versions"`
	ProjectNames []string           `json:"project_names"`
	SecretNames  []string           `json:"secret_names"`
	RoleNames    []string           `json:"role_names"`
	KeyBlobsB64  []string           `json:"key_blobs_b64"`
}

type xverKnownVersion struct {
	NodeID       uint   `json:"node_id"`
	ProjectID    uint   `json:"project_id"`
	Version      int    `json:"version"`
	PlaintextB64 string `json:"plaintext_b64"`
}

// xverLoadFixture reads the frozen archive bytes and the expected sidecar. It MUST
// be called before any chdir (restoreInto/setupSource chdir away from the package
// dir), i.e. at the very top of a test / f.Fuzz setup.
func xverLoadFixture(t testing.TB) (archive []byte, exp xverExpected) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(xverFixtureDir, xverV2Archive))
	require.NoError(t, err, "frozen fixture missing -- regenerate with KEYORIX_GEN_XVER_FIXTURE=1")
	ej, err := os.ReadFile(filepath.Join(xverFixtureDir, xverV2Expected))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(ej, &exp))
	require.NotEmpty(t, exp.Versions, "fixture must record at least one canary version")
	return raw, exp
}

// xverKnownToModel converts the recorded versions into this package's knownVersion
// shape so oracleDecrypt can re-derive each AAD and decrypt.
func xverKnownToModel(t testing.TB, exp xverExpected) []knownVersion {
	t.Helper()
	known := make([]knownVersion, 0, len(exp.Versions))
	for _, v := range exp.Versions {
		pt, err := base64.StdEncoding.DecodeString(v.PlaintextB64)
		require.NoError(t, err)
		known = append(known, knownVersion{nodeID: v.NodeID, projectID: v.ProjectID, version: v.Version, plaintext: pt})
	}
	return known
}

// xverSecrets returns the byte strings that must never appear in restore output
// (O4): every recorded canary plaintext and every throwaway key-file blob.
func xverSecrets(t testing.TB, exp xverExpected) [][]byte {
	t.Helper()
	var out [][]byte
	for _, v := range exp.Versions {
		pt, err := base64.StdEncoding.DecodeString(v.PlaintextB64)
		require.NoError(t, err)
		if len(pt) > 0 {
			out = append(out, pt)
		}
	}
	for _, b := range exp.KeyBlobsB64 {
		kb, err := base64.StdEncoding.DecodeString(b)
		require.NoError(t, err)
		if len(kb) > 0 {
			out = append(out, kb)
		}
	}
	return out
}

// xverRestore restores archivePath into a fresh SQLite dir with the given caps
// (0 => reader defaults) and leaves the process chdir'd in the dst dir. Mirrors
// restoreInto but exposes the caps so O3 can drive tiny ones.
func xverRestore(t *testing.T, archivePath string, maxEntry, maxTotal int64) (string, string, error) {
	t.Helper()
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = bkConfigureBackend(t, "sqlite", dstDir, "")
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = maxEntry
	restoreMaxTotalBytes = maxTotal
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	return dstDir, out, err
}

// xverAssertO1 restores the pristine fixture and asserts decrypt-to-recorded-
// plaintext plus metadata round-trip.
func xverAssertO1(t *testing.T, archivePath string, exp xverExpected, known []knownVersion) {
	t.Helper()
	dstDir, out, err := xverRestore(t, archivePath, 0, 0)
	require.NoError(t, err, "O1: the pristine frozen fixture must restore cleanly (stdout: %s)", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID",
		"O1: restore must verify the audit chain on the restored store")

	dstCfg, err := loadConfig() // we are chdir'd in dstDir
	require.NoError(t, err)

	oracleDecrypt(t, dstDir, dstCfg, known) // O1 decrypt-to-recorded-plaintext

	gdb, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)

	// oracleDecrypt tolerates a MISSING version row (a deleted secret), so on its
	// own it cannot tell "this version decrypts" from "this version silently
	// vanished." Pin the restored row count to what the fixture recorded, so a
	// reader that silently dropped a version/table (the "drop support silently"
	// regression) is caught here rather than passing vacuously.
	var versionCount int64
	require.NoError(t, gdb.Table("secret_versions").Count(&versionCount).Error)
	require.Equal(t, int64(len(exp.Versions)), versionCount,
		"O1: every recorded secret version must be present after restore (no silent drop)")

	xverAssertMetadata(t, gdb, exp)
}

// xverAssertMetadata asserts the restored store's project/role/secret names equal
// what the fixture recorded -- metadata round-trips, not just the ciphertext.
func xverAssertMetadata(t *testing.T, gdb *gorm.DB, exp xverExpected) {
	t.Helper()
	var projects []models.Project
	require.NoError(t, gdb.Order("id").Find(&projects).Error)
	gotProjects := make([]string, 0, len(projects))
	for _, p := range projects {
		gotProjects = append(gotProjects, p.Name)
	}
	require.Equal(t, exp.ProjectNames, gotProjects, "O1: project metadata must round-trip")

	var secretNodes []models.SecretNode
	require.NoError(t, gdb.Order("id").Find(&secretNodes).Error)
	gotSecrets := make([]string, 0, len(secretNodes))
	for _, s := range secretNodes {
		gotSecrets = append(gotSecrets, s.Name)
	}
	require.Equal(t, exp.SecretNames, gotSecrets, "O1: secret metadata must round-trip")

	var roles []models.Role
	require.NoError(t, gdb.Order("id").Find(&roles).Error)
	gotRoles := make([]string, 0, len(roles))
	for _, r := range roles {
		gotRoles = append(gotRoles, r.Name)
	}
	require.Equal(t, exp.RoleNames, gotRoles, "O1: role metadata must round-trip")
}

// xverAssertNoLeak fails if any canary/key byte string appears in text (O4).
func xverAssertNoLeak(t *testing.T, text string, secrets [][]byte) {
	t.Helper()
	for _, s := range secrets {
		if bytes.Contains([]byte(text), s) {
			// Never print the secret itself; report only that it leaked and its length.
			t.Fatalf("O4: a %d-byte canary/key byte string leaked into restore output/error", len(s))
		}
	}
}

// xverAssertNoRestoredState asserts a REFUSED restore left no half-restored rows in
// the destination store (O2). We are chdir'd in dstDir. If no DB file exists the
// restore committed nothing, which is clean; otherwise the secret_versions table
// must be empty.
func xverAssertNoRestoredState(t *testing.T, dstDir string) {
	t.Helper()
	dbPath := filepath.Join(dstDir, "secrets.db")
	if _, err := os.Stat(dbPath); err != nil {
		return // no DB written at all -- a refused restore committed nothing
	}
	cfg, err := loadConfig()
	if err != nil {
		return
	}
	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		return
	}
	// Check several load-bearing tables, not just one: a failure midway through a
	// multi-table load could leave rows in a table that loaded before the failing
	// one (restore order loads parents first), so checking only secret_versions
	// would miss a partial state in projects/secret_nodes/users.
	for _, table := range []string{"projects", "environments", "secret_nodes", "secret_versions", "roles", "machine_identities"} {
		var n int64
		if err := gdb.Table(table).Count(&n).Error; err == nil {
			require.Zero(t, n, "O2: a refused restore left %q rows behind (half-restored state)", table)
		}
	}
}

// TestXverRestore_O1_DecryptsAndMetadata is the deterministic cross-version oracle:
// the frozen fixture restores and every canary decrypts, metadata round-trips.
func TestXverRestore_O1_DecryptsAndMetadata(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	archiveBytes, exp := xverLoadFixture(t)
	known := xverKnownToModel(t, exp)

	archivePath := filepath.Join(t.TempDir(), "fixture.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, archiveBytes, 0o600))

	xverAssertO1(t, archivePath, exp, known)
}

// TestXverRestore_O3_BoundedHostileLength drives tiny caps and asserts a prompt,
// bounded refusal (resguard): the reader stops at the cap, never buffers the whole
// payload.
func TestXverRestore_O3_BoundedHostileLength(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	archiveBytes, exp := xverLoadFixture(t)
	archivePath := filepath.Join(t.TempDir(), "fixture.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, archiveBytes, 0o600))

	start := time.Now()
	_, out, err := xverRestore(t, archivePath, 256, 256) // 256-byte caps: the fixture dwarfs them
	require.Error(t, err, "O3: tiny caps must refuse the fixture, not buffer it (stdout: %s)", out)
	require.Less(t, time.Since(start), 30*time.Second, "O3: refusal must be prompt, not a hang")
	xverAssertNoLeak(t, err.Error()+out, xverSecrets(t, exp)) // O4 on the refusal too
}

func FuzzXverRestore(f *testing.F) {
	require.NoError(f, i18n.InitializeForTesting())

	archiveBytes, exp := xverLoadFixture(f) // read BEFORE the fuzz loop (cwd = package dir)
	known := xverKnownToModel(f, exp)
	secrets := xverSecrets(f, exp)

	f.Add(archiveBytes)                                  // pristine: O1 must hold
	f.Add(archiveBytes[:len(archiveBytes)/2])            // truncation
	f.Add(append(bytes.Clone(archiveBytes), 0, 1, 2, 3)) // trailing/oversize bytes
	f.Add([]byte{})                                      // empty
	if m := xverBitFlip(archiveBytes, 17); m != nil {
		f.Add(m) // single bit flip deep in the payload
	}
	if m := xverBitFlip(archiveBytes, len(archiveBytes)/2); m != nil {
		f.Add(m)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		resetBackupRestoreFlags(t)
		t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

		archivePath := filepath.Join(t.TempDir(), "in.tar.gz")
		require.NoError(t, os.WriteFile(archivePath, b, 0o600))

		start := time.Now()
		dstDir, out, err := xverRestore(t, archivePath, 0, 0)
		if el := time.Since(start); el > 60*time.Second {
			t.Fatalf("XVER-SLOW-EXEC: restore took %s on a %d-byte input", el, len(b))
		}

		if err != nil {
			// O2 (fail-closed), O4 (no leak in the refusal), and no half-restored state.
			xverAssertNoLeak(t, err.Error()+out, secrets)
			xverAssertNoRestoredState(t, dstDir)
			return
		}

		// Restore SUCCEEDED. Either b is the pristine fixture or a mutation that still
		// produced a loadable archive; in both cases O1 must hold for whatever survived
		// (oracleDecrypt skips rows that a deletion mutation legitimately removed), and
		// a successful restore must not have leaked a secret into its stdout either.
		xverAssertNoLeak(t, out, secrets)
		dstCfg, cerr := loadConfig()
		require.NoError(t, cerr)
		oracleDecrypt(t, dstDir, dstCfg, known)
	})
}

// --- v2 archive surgery, for the enumerated structural mutations (O2) ---

type xverEntry struct {
	name string
	data []byte
}

// xverUnpack gunzips+untars an archive into its ordered entries.
func xverUnpack(t *testing.T, archive []byte) []xverEntry {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var entries []xverEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		entries = append(entries, xverEntry{name: hdr.Name, data: data})
	}
	require.NoError(t, gz.Close())
	return entries
}

// xverRepack writes entries back to a gzipped tar, verbatim and in order.
func xverRepack(t *testing.T, entries []xverEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data))}))
		_, err := tw.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// xverManifestOf returns the index of the MANIFEST.json entry (always first).
func xverManifestIndex(t *testing.T, entries []xverEntry) int {
	t.Helper()
	for i, e := range entries {
		if e.name == "MANIFEST.json" {
			return i
		}
	}
	t.Fatal("MANIFEST.json entry not found")
	return -1
}

// xverMutateManifest decodes the manifest, applies fn, and re-encodes it in place.
func xverMutateManifest(t *testing.T, entries []xverEntry, fn func(*backupfmt.Manifest)) []xverEntry {
	t.Helper()
	idx := xverManifestIndex(t, entries)
	var m backupfmt.Manifest
	require.NoError(t, json.Unmarshal(entries[idx].data, &m))
	fn(&m)
	raw, err := json.MarshalIndent(&m, "", "  ")
	require.NoError(t, err)
	out := make([]xverEntry, len(entries))
	copy(out, entries)
	out[idx] = xverEntry{name: "MANIFEST.json", data: raw}
	return out
}

// xverFirstTableIndex returns the index of the first tables/*.ndjson entry with a
// non-empty payload (so a bit flip actually changes restored content).
func xverFirstNonEmptyTableIndex(entries []xverEntry) int {
	for i, e := range entries {
		if len(e.data) > 0 && len(e.name) > len("tables/") && e.name[:len("tables/")] == "tables/" {
			return i
		}
	}
	return -1
}

// TestXverRestore_O2_Mutations drives the brief's enumerated structural mutations
// through the FULL restore path and asserts the O2 contract on each: a restore
// either SUCCEEDS with O1 intact, or is REFUSED with an explicit error that leaks
// no secret (O4) and leaves no half-restored rows. The contract itself cannot
// false-positive (the success branch re-checks O1); the per-case `expectRefusal`
// only documents and additionally pins the shape we believe must be rejected.
func TestXverRestore_O2_Mutations(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	archiveBytes, exp := xverLoadFixture(t)
	known := xverKnownToModel(t, exp)
	secrets := xverSecrets(t, exp)
	base := xverUnpack(t, archiveBytes)

	cases := []struct {
		name          string
		build         func(t *testing.T) []byte
		expectRefusal bool
	}{
		{
			name: "payload-bit-flip", // per-entry sha256 must catch it
			build: func(t *testing.T) []byte {
				idx := xverFirstNonEmptyTableIndex(base)
				require.GreaterOrEqual(t, idx, 0)
				m := make([]xverEntry, len(base))
				copy(m, base)
				d := bytes.Clone(base[idx].data)
				d[len(d)/2] ^= 0x20
				m[idx] = xverEntry{name: base[idx].name, data: d}
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
		{
			// Corrupts the secret's ciphertext while keeping the NDJSON line
			// structurally valid (same length, valid JSON, unchanged row count) so
			// the ONLY guardian left between it and a wrong restored plaintext is the
			// per-entry SHA-256 in ExtractArchive. The correct reader refuses here;
			// a reader that skipped the checksum would load corrupted ciphertext and
			// O1's oracleDecrypt would then fail (that is this case's red proof).
			name: "secret-value-corrupted",
			build: func(t *testing.T) []byte {
				return xverCorruptSecretValue(t, base)
			},
			expectRefusal: true,
		},
		{
			// Corrupts the secret ciphertext AND rewrites the manifest's per-entry
			// SHA-256 to match the corrupted bytes, so the content checksum passes and
			// the ONLY guardian left is the manifest's HMAC signature (which this
			// tamper does not and cannot re-forge without the KEK-derived key). The
			// correct reader refuses at the signature gate; a reader that skipped
			// signature verification would load corrupted ciphertext (red proof).
			name: "signature-tamper-sha-consistent",
			build: func(t *testing.T) []byte {
				return xverSignatureTamper(t, base)
			},
			expectRefusal: true,
		},
		{
			// Drops a metadata table whose rows the manifest still lists. The correct
			// reader refuses (loadTable cannot open the missing staged file); a reader
			// that treated a missing staged file as an empty table would silently lose
			// the project row and O1's metadata assertion would fail (red proof).
			name: "dropped-projects-table",
			build: func(t *testing.T) []byte {
				m := make([]xverEntry, 0, len(base))
				for _, e := range base {
					if e.name == "tables/projects.ndjson" {
						continue
					}
					m = append(m, e)
				}
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
		{
			name: "duplicated-entry",
			build: func(t *testing.T) []byte {
				idx := xverFirstNonEmptyTableIndex(base)
				require.GreaterOrEqual(t, idx, 0)
				m := append([]xverEntry{}, base...)
				m = append(m, base[idx]) // append an exact duplicate of a table entry
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
		{
			name: "reordered-manifest-not-first",
			build: func(t *testing.T) []byte {
				require.Equal(t, "MANIFEST.json", base[0].name)
				m := append([]xverEntry{}, base...)
				m[0], m[1] = m[1], m[0] // MANIFEST.json no longer first
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
		{
			name: "wrong-version-tag",
			build: func(t *testing.T) []byte {
				m := xverMutateManifest(t, base, func(mf *backupfmt.Manifest) { mf.FormatVersion = 99 })
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
		{
			name: "oversize-length-field",
			build: func(t *testing.T) []byte {
				m := xverMutateManifest(t, base, func(mf *backupfmt.Manifest) {
					for i := range mf.Tables {
						mf.Tables[i].UncompressedSize = 1 << 40 // 1 TiB declared
					}
				})
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
		{
			name: "dropped-table-entry",
			build: func(t *testing.T) []byte {
				idx := xverFirstNonEmptyTableIndex(base)
				require.GreaterOrEqual(t, idx, 0)
				m := make([]xverEntry, 0, len(base)-1)
				m = append(m, base[:idx]...)
				m = append(m, base[idx+1:]...) // manifest still lists the table; its entry is gone
				return xverRepack(t, m)
			},
			expectRefusal: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

			mutated := tc.build(t)
			archivePath := filepath.Join(t.TempDir(), "mut.tar.gz")
			require.NoError(t, os.WriteFile(archivePath, mutated, 0o600))

			dstDir, out, err := xverRestore(t, archivePath, 0, 0)
			if err != nil {
				// Fail-closed: no secret leaked, no half-restored state.
				xverAssertNoLeak(t, err.Error()+out, secrets)
				xverAssertNoRestoredState(t, dstDir)
				return
			}
			// Accepted: O1 must still hold exactly (no silent corruption).
			require.False(t, tc.expectRefusal,
				"O2: mutation %q was expected to be refused but restore accepted it", tc.name)
			xverAssertNoLeak(t, out, secrets)
			dstCfg, cerr := loadConfig()
			require.NoError(t, cerr)
			oracleDecrypt(t, dstDir, dstCfg, known)
		})
	}
}

// xverCorruptSecretValue changes one base64 character of the first secret
// version's EncryptedValue in tables/secret_versions.ndjson, keeping the NDJSON
// line valid JSON of the same length and the row count unchanged -- so the staged
// file differs ONLY in the ciphertext bytes, isolating the per-entry SHA-256 check.
func xverCorruptSecretValue(t *testing.T, base []xverEntry) []byte {
	t.Helper()
	const tbl = "tables/secret_versions.ndjson"
	out := make([]xverEntry, len(base))
	copy(out, base)
	for i, e := range base {
		if e.name != tbl {
			continue
		}
		d := bytes.Clone(e.data)
		marker := []byte(`"EncryptedValue":"`)
		k := bytes.Index(d, marker)
		require.GreaterOrEqual(t, k, 0, "EncryptedValue field not found in %s", tbl)
		p := k + len(marker) // first base64 char of the value
		require.Less(t, p, len(d))
		if d[p] == 'A' { // swap for a different, still-valid base64 alphabet char
			d[p] = 'B'
		} else {
			d[p] = 'A'
		}
		out[i] = xverEntry{name: e.name, data: d}
		return xverRepack(t, out)
	}
	t.Fatalf("%s entry not found", tbl)
	return nil
}

// xverSignatureTamper corrupts the secret ciphertext and rewrites the matching
// manifest TableEntry's SHA-256 (and size, unchanged) to the corrupted bytes, so
// ExtractArchive's per-entry checksum passes and only the manifest signature stands
// between the tamper and a corrupted restore.
func xverSignatureTamper(t *testing.T, base []xverEntry) []byte {
	t.Helper()
	const tbl = "tables/secret_versions.ndjson"
	// Step 1: corrupt the ciphertext (reuse xverCorruptSecretValue's edit, but keep
	// the entries so we can recompute the manifest).
	entries := make([]xverEntry, len(base))
	copy(entries, base)
	var corrupted []byte
	for i, e := range base {
		if e.name != tbl {
			continue
		}
		d := bytes.Clone(e.data)
		marker := []byte(`"EncryptedValue":"`)
		k := bytes.Index(d, marker)
		require.GreaterOrEqual(t, k, 0)
		p := k + len(marker)
		if d[p] == 'A' {
			d[p] = 'B'
		} else {
			d[p] = 'A'
		}
		corrupted = d
		entries[i] = xverEntry{name: e.name, data: d}
	}
	require.NotNil(t, corrupted, "%s not found", tbl)
	newSum := sha256.Sum256(corrupted)
	// Step 2: rewrite the manifest's SHA-256 for that table to the corrupted bytes.
	entries = xverMutateManifest(t, entries, func(m *backupfmt.Manifest) {
		for i := range m.Tables {
			if m.Tables[i].TarName == tbl {
				m.Tables[i].SHA256 = hex.EncodeToString(newSum[:])
				m.Tables[i].UncompressedSize = int64(len(corrupted))
			}
		}
	})
	return xverRepack(t, entries)
}

// xverBitFlip returns a copy of src with one bit flipped at byte i, or nil if i is
// out of range.
func xverBitFlip(src []byte, i int) []byte {
	if i < 0 || i >= len(src) {
		return nil
	}
	m := bytes.Clone(src)
	m[i] ^= 0x40
	return m
}

// TestXverGenerateFixture regenerates the frozen fixture + sidecar from the REAL
// current writer. Gated behind KEYORIX_GEN_XVER_FIXTURE so an ordinary `go test`
// never rewrites committed bytes.
func TestXverGenerateFixture(t *testing.T) {
	if os.Getenv("KEYORIX_GEN_XVER_FIXTURE") == "" {
		t.Skip("set KEYORIX_GEN_XVER_FIXTURE=1 to regenerate the frozen fixture")
	}
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	origWD, err := os.Getwd()
	require.NoError(t, err)

	// Deterministic program (4 bytes/op, see applyOp): create project, create
	// secret (v1), add a version (v2), create a role, create a machine identity --
	// enough to exercise decrypt (two versions) and metadata (project/role/secret).
	program := []byte{
		0, 0, 0, 0, // create project    -> proj-1 (+ env)
		1, 0, 0, 0, // create secret     -> secret-2, version 1, "plaintext-2-0"
		3, 0, 0, 0, // add a version      -> version 2, "plaintext-v-3-0"
		5, 0, 0, 0, // create role       -> role-4
		6, 0, 0, 0, // create machine id  -> mi-5
	}
	src := setupSource(t, "sqlite", "", program)
	require.NotEmpty(t, src.model.known, "seed program must create at least one secret version")

	// Capture the throwaway key-file bytes from the source before backing up.
	dekBytes, err := os.ReadFile(filepath.Join(src.dir, "dek.key"))
	require.NoError(t, err)
	saltBytes, err := os.ReadFile(filepath.Join(src.dir, "kek.salt"))
	require.NoError(t, err)

	archive := filepath.Join(t.TempDir(), "gen.tar.gz")
	manifest, _, out, err := backupTables(t, archive)
	require.NoError(t, err, "generate: backup must succeed (stdout: %s)", out)
	require.NotEmpty(t, manifest.Tables)

	raw, err := os.ReadFile(archive)
	require.NoError(t, err)

	exp := xverExpected{Format: "v2", Passphrase: roundTripPassphrase}
	for _, kv := range src.model.known {
		exp.Versions = append(exp.Versions, xverKnownVersion{
			NodeID: kv.nodeID, ProjectID: kv.projectID, Version: kv.version,
			PlaintextB64: base64.StdEncoding.EncodeToString(kv.plaintext),
		})
	}
	var projects []models.Project
	require.NoError(t, src.gdb.Order("id").Find(&projects).Error)
	for _, p := range projects {
		exp.ProjectNames = append(exp.ProjectNames, p.Name)
	}
	var secretNodes []models.SecretNode
	require.NoError(t, src.gdb.Order("id").Find(&secretNodes).Error)
	for _, s := range secretNodes {
		exp.SecretNames = append(exp.SecretNames, s.Name)
	}
	var roles []models.Role
	require.NoError(t, src.gdb.Order("id").Find(&roles).Error)
	for _, r := range roles {
		exp.RoleNames = append(exp.RoleNames, r.Name)
	}
	exp.KeyBlobsB64 = []string{
		base64.StdEncoding.EncodeToString(dekBytes),
		base64.StdEncoding.EncodeToString(saltBytes),
	}

	outDir := filepath.Join(origWD, xverFixtureDir)
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, xverV2Archive), raw, 0o644))
	sidecar, err := json.MarshalIndent(exp, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(outDir, xverV2Expected), sidecar, 0o644))
	t.Logf("wrote %s (%d bytes) + %s (%d versions, %d projects, %d roles)",
		xverV2Archive, len(raw), xverV2Expected, len(exp.Versions), len(exp.ProjectNames), len(exp.RoleNames))
}
