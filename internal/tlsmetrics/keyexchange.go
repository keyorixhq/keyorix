package tlsmetrics

import (
	"crypto/tls"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var handshakes = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_tls_handshakes_total",
	Help: "Completed TLS handshakes by listener (http|grpc) and the key-exchange group negotiated (X25519MLKEM768 is the post-quantum hybrid; X25519/P-256/... are classical; none = no ECDHE group, e.g. a TLS 1.2 RSA key exchange). Counts a connection when its handshake finishes; a resumed session counts again.",
}, []string{"listener", "group"})

// GroupName maps a negotiated key-exchange group to a label from a closed set, so
// a peer cannot mint metric series by offering exotic groups. Groups this server
// can negotiate are named; anything else is "other"; a zero CurveID (no ECDHE
// group was used) is "none".
func GroupName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.SecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	case tls.SecP384r1MLKEM1024:
		return "SecP384r1MLKEM1024"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case 0:
		return "none"
	default:
		return "other"
	}
}

// IsPostQuantum reports whether id is a hybrid group with an ML-KEM component.
func IsPostQuantum(id tls.CurveID) bool {
	switch id {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	}
	return false
}

// ObserveHandshake returns a tls.Config.VerifyConnection hook that counts each
// completed handshake on listener under the key-exchange group it negotiated. It
// only observes: it never returns an error, so it cannot refuse a connection
// (requiring a post-quantum group is a separate policy decision, not made here).
func ObserveHandshake(listener string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		handshakes.WithLabelValues(listener, GroupName(cs.CurveID)).Inc()
		return nil
	}
}
