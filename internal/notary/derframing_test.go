package notary

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedCorpusBytes decodes a Go fuzz seed-corpus file (`go test fuzz v1` header
// followed by a single `[]byte("...")` argument) into the raw input bytes.
func seedCorpusBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	s := string(b)
	i := strings.Index(s, "[]byte(")
	require.GreaterOrEqual(t, i, 0, "not a []byte fuzz corpus entry")
	lit := strings.TrimSuffix(strings.TrimSpace(s[i+len("[]byte("):]), ")")
	u, err := strconv.Unquote(lit)
	require.NoError(t, err)
	return []byte(u)
}

// The five inputs the continuous-fuzz rig found (2026-07..08) and that never
// reached the repo: malformed RFC 3161 tokens that drive digitorus/pkcs7's BER
// decoder into allocating gigabytes. They are committed as FuzzVerifyReceipt
// seed corpus so the target keeps them, and exercised directly here.
func amplificationCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	files, err := filepath.Glob("testdata/fuzz/FuzzVerifyReceipt/*")
	require.NoError(t, err)
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		out[filepath.Base(f)] = seedCorpusBytes(t, b)
	}
	require.NotEmpty(t, out)
	return out
}

// TestValidateDERFraming_RejectsAmplificationCorpus is the core regression:
// every archived reproducer must be rejected by the framing guard.
func TestValidateDERFraming_RejectsAmplificationCorpus(t *testing.T) {
	for name, in := range amplificationCorpus(t) {
		if err := validateDERFraming(in); err == nil {
			t.Errorf("%s: validateDERFraming accepted a known decoder-amplification input", name)
		}
	}
}

// TestVerifyReceipt_AmplificationInputIsCheap proves the guard short-circuits
// before the decoder: the worst reproducer used to allocate ~1.8 GB and run ~1 s;
// with the guard VerifyReceipt must return an error almost instantly and barely
// allocate. A generous ceiling (200 ms wall, 64 MiB) still fails hard if the
// guard is ever removed or bypassed — the unguarded path is orders of magnitude
// past it.
func TestVerifyReceipt_AmplificationInputIsCheap(t *testing.T) {
	roots := x509.NewCertPool() // non-nil so we reach the framing check, not the nil-roots guard
	for name, in := range amplificationCorpus(t) {
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		start := time.Now()
		_, err := VerifyReceipt(roots, []byte("m"), in)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		require.Error(t, err, "%s must be rejected", name)
		assert.Less(t, elapsed, 200*time.Millisecond, "%s took %v — guard not short-circuiting", name, elapsed)
		assert.Less(t, alloc, uint64(64<<20), "%s allocated %d bytes — guard not short-circuiting", name, alloc)
	}
}

// TestValidateDERFraming_RejectsScaledBomb covers the tunable definite-length
// shape whose cost doubles with each added unit (147 bytes -> 28 GB unguarded).
func TestValidateDERFraming_RejectsScaledBomb(t *testing.T) {
	base := []byte("0\r\r\x020\x020\x02")
	for _, k := range []int{1, 4, 8, 16, 64} {
		in := append(append([]byte{}, base...), bytes.Repeat([]byte("0\x020 "), k)...)
		assert.Error(t, validateDERFraming(in), "scaled bomb k=%d must be rejected", k)
	}
}

// TestValidateDERFraming_AcceptsRealToken is the positive path: a genuine
// validly-signed token, and the full TSA response it came in, must both pass —
// the guard must not reject anything legitimate.
func TestValidateDERFraming_AcceptsRealToken(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	msg := []byte("checkpoint bytes being anchored")
	want := sha256.Sum256(msg)
	token, cert := craftTokenWithHashAlgorithm(t, fixedTime, crypto.SHA256, want[:])

	assert.NoError(t, validateDERFraming(token), "real token must pass framing")

	// And it must still fully verify end-to-end with the guard in place.
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	at, err := VerifyReceipt(roots, msg, token)
	require.NoError(t, err)
	assert.WithinDuration(t, fixedTime, at, time.Second)
}

// TestValidateDERFraming_Framing spot-checks the individual rejection reasons so
// the guard's own logic is covered, not just the corpus.
func TestValidateDERFraming_Framing(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"minimal SEQUENCE{}", []byte{0x30, 0x00}, true},
		{"SEQUENCE with one NULL child", []byte{0x30, 0x02, 0x05, 0x00}, true},
		{"indefinite length", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}, false},
		{"child overruns parent", []byte{0x30, 0x02, 0x30, 0x20}, false},
		{"trailing bytes", []byte{0x05, 0x00, 0x05, 0x00}, false},
		{"length past buffer", []byte{0x04, 0x7f}, false},
		{"truncated header", []byte{0x30}, false},
	}
	for _, c := range cases {
		err := validateDERFraming(c.in)
		if c.ok {
			assert.NoErrorf(t, err, "%s should be accepted", c.name)
		} else {
			assert.Errorf(t, err, "%s should be rejected", c.name)
		}
	}
}
