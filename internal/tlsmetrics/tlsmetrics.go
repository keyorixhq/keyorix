// Package tlsmetrics exposes the expiry time of the certificate each TLS listener
// is serving, so an expiring server certificate is an alert rather than an outage.
//
// The certificate is read once at listener start (the servers load their key pair
// statically), so the gauge is exactly what clients are being handed. The cert's
// NotAfter is already public to anyone who connects, so it is safe on /metrics.
// The listener label is one of the two constants below.
package tlsmetrics

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Listener names. These are the only values the listener label can take.
const (
	HTTP = "http"
	GRPC = "grpc"
)

var notAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "keyorix_tls_certificate_not_after_timestamp_seconds",
	Help: "Unix time at which the TLS certificate served by a listener (http|grpc) expires. Alert on this minus time() before it reaches zero; certificates are loaded at start, so a renewed file needs a restart to take effect.",
}, []string{"listener"})

// Observe records the expiry of the leaf certificate cert serves on listener. A
// certificate that cannot be parsed records nothing (the listener would already
// have failed to start with it).
func Observe(listener string, cert tls.Certificate) {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return
		}
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return
		}
	}
	notAfter.WithLabelValues(listener).Set(float64(leaf.NotAfter.Unix()))
}
