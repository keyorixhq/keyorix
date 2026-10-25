package tlsmetrics

import (
	"crypto/tls"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupName_ClosedSet(t *testing.T) {
	cases := map[tls.CurveID]string{
		tls.X25519MLKEM768:      "X25519MLKEM768",
		tls.SecP256r1MLKEM768:   "SecP256r1MLKEM768",
		tls.SecP384r1MLKEM1024:  "SecP384r1MLKEM1024",
		tls.X25519:              "X25519",
		tls.CurveP256:           "P-256",
		tls.CurveP384:           "P-384",
		tls.CurveP521:           "P-521",
		0:                       "none",
		tls.CurveID(0xdead):     "other",
		tls.CurveID(0x6399):     "other", // X25519Kyber768Draft00: not offered by Go, must not mint a label
		tls.CurveID(0x0100 + 1): "other",
	}
	for id, want := range cases {
		assert.Equal(t, want, GroupName(id), "CurveID %#x", uint16(id))
	}
}

func TestIsPostQuantum(t *testing.T) {
	assert.True(t, IsPostQuantum(tls.X25519MLKEM768))
	assert.True(t, IsPostQuantum(tls.SecP256r1MLKEM768))
	assert.True(t, IsPostQuantum(tls.SecP384r1MLKEM1024))
	assert.False(t, IsPostQuantum(tls.X25519))
	assert.False(t, IsPostQuantum(tls.CurveP256))
	assert.False(t, IsPostQuantum(0))
}

func TestObserveHandshake_CountsPerListenerAndGroup(t *testing.T) {
	hook := ObserveHandshake("kxtest")
	require.NoError(t, hook(tls.ConnectionState{CurveID: tls.X25519MLKEM768}))
	require.NoError(t, hook(tls.ConnectionState{CurveID: tls.X25519MLKEM768}))
	require.NoError(t, hook(tls.ConnectionState{CurveID: tls.X25519}))

	assert.Equal(t, 2.0, testutil.ToFloat64(handshakes.WithLabelValues("kxtest", "X25519MLKEM768")))
	assert.Equal(t, 1.0, testutil.ToFloat64(handshakes.WithLabelValues("kxtest", "X25519")))
}

func TestObserveHandshake_NeverRefusesAConnection(t *testing.T) {
	hook := ObserveHandshake("kxtest2")
	for _, id := range []tls.CurveID{0, tls.X25519, tls.CurveID(0xdead)} {
		assert.NoError(t, hook(tls.ConnectionState{CurveID: id}), "observing must not turn into a policy decision (CurveID %#x)", uint16(id))
	}
}
