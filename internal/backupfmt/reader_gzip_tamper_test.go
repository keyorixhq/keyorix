package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"testing"

	"github.com/stretchr/testify/require"
)

// gzipTamperEntry is deliberately not a multiple of the 512-byte tar block, so
// the entry is followed by padding the tar reader skips without reading.
const gzipTamperEntry = "tables/pad.ndjson"

// gzipTamperTar returns an uncompressed tar (MANIFEST.json + one table entry)
// and the offset of the first padding byte after the table entry's data.
func gzipTamperTar(t *testing.T) (tarBytes []byte, padOffset int) {
	t.Helper()
	data := bytes.Repeat([]byte("x"), 100)
	sum := sha256.Sum256(data)
	m, err := json.Marshal(Manifest{FormatVersion: FormatVersion, Backend: Backend, Tables: []TableEntry{{
		Name: "pad", TarName: gzipTamperEntry, UncompressedSize: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
	}}})
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "MANIFEST.json", Mode: 0600, Size: int64(len(m)), Typeflag: tar.TypeReg}))
	_, err = tw.Write(m)
	require.NoError(t, err)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: gzipTamperEntry, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}))
	_, err = tw.Write(data)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	padOffset = 512 + (len(m)+511)/512*512 + 512 + len(data)
	require.Zero(t, buf.Bytes()[padOffset], "fixture: expected a zero padding byte at %d", padOffset)
	return buf.Bytes(), padOffset
}

// gzipWithCRCOf gzips payload but writes the trailer (CRC-32, ISIZE) of
// trailerOf, i.e. what a flipped byte in the plaintext looks like to a reader
// that checks the original checksum.
func gzipWithCRCOf(t *testing.T, payload, trailerOf []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	out.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	fw, err := flate.NewWriter(&out, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = fw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, fw.Close())
	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[:4], crc32.ChecksumIEEE(trailerOf))
	binary.LittleEndian.PutUint32(trailer[4:], uint32(len(trailerOf))) // #nosec G115 -- fixture is a few KiB
	out.Write(trailer[:])
	return out.Bytes()
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	_, err := gz.Write(payload)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return out.Bytes()
}

// TestExtractArchive_RefusesGzipTamper: the tar reader never reads entry
// padding or anything after the end-of-archive marker, so before the gzip
// stream was drained to EOF a flipped byte in padding (checksum unchanged) or
// in the gzip trailer was accepted (scripts/airgap-e2e.sh "admin restore
// accepted a tampered archive" flake).
func TestExtractArchive_RefusesGzipTamper(t *testing.T) {
	tarBytes, padOffset := gzipTamperTar(t)

	t.Run("untouched archive extracts", func(t *testing.T) {
		m, err := ExtractArchive(bytes.NewReader(gzipBytes(t, tarBytes)), t.TempDir(), 0, 0)
		require.NoError(t, err)
		require.Len(t, m.Tables, 1)
	})

	t.Run("flipped byte in tar padding", func(t *testing.T) {
		flipped := bytes.Clone(tarBytes)
		flipped[padOffset] ^= 0x01
		_, err := ExtractArchive(bytes.NewReader(gzipWithCRCOf(t, flipped, tarBytes)), t.TempDir(), 0, 0)
		require.ErrorIs(t, err, gzip.ErrChecksum)
	})

	t.Run("flipped byte in gzip trailer", func(t *testing.T) {
		gz := gzipBytes(t, tarBytes)
		gz[len(gz)-8] ^= 0x01 // CRC-32 field
		_, err := ExtractArchive(bytes.NewReader(gz), t.TempDir(), 0, 0)
		require.ErrorIs(t, err, gzip.ErrChecksum)
	})

	t.Run("truncated gzip trailer", func(t *testing.T) {
		gz := gzipBytes(t, tarBytes)
		_, err := ExtractArchive(bytes.NewReader(gz[:len(gz)-4]), t.TempDir(), 0, 0)
		require.Error(t, err)
	})

	t.Run("trailing data after the tar end is capped", func(t *testing.T) {
		padded := append(bytes.Clone(tarBytes), make([]byte, 4096)...)
		_, err := ExtractArchive(bytes.NewReader(gzipBytes(t, padded)), t.TempDir(), 0, 1024)
		require.Error(t, err)
	})
}
