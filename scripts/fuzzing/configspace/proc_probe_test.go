package configspace

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSignedLikeAdminInit returns a certificate shaped like the one admin init writes
// (ensureSelfSignedCert: self-signed, DNS name localhost, loopback IPs) and its PEM.
func selfSignedLikeAdminInit(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "configspace probe test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func probeCase(t *testing.T, certPEM []byte) *Case {
	t.Helper()
	dir := t.TempDir()
	if certPEM != nil {
		if err := os.MkdirAll(filepath.Join(dir, "certs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "certs", "server.crt"), certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Case{ID: "probe", Dir: dir, Doc: map[string]any{}}
}

// TestProbeHTTPPinsTheCaseCertificate checks the process-stage probe's TLS client: it
// reaches a server presenting the case's own certificate, and refuses one presenting any
// other certificate (the old InsecureSkipVerify probe got 200 there) or when the case has
// no certificate to pin. It does NOT verify the probe against the real binary; the
// process stage of TestMatrix does that.
func TestProbeHTTPPinsTheCaseCertificate(t *testing.T) {
	served, servedPEM := selfSignedLikeAdminInit(t)
	_, otherPEM := selfSignedLikeAdminInit(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{served}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	cases := []struct {
		name     string
		pem      []byte
		want     int
		bodyHint string
	}{
		{"case certificate", servedPEM, 200, "200 ok"},
		{"foreign certificate", otherPEM, 0, "certificate"},
		{"no certificate", nil, 0, "ERR harness:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := probeCase(t, tc.pem)
			res := ProcResult{Bodies: map[string]string{}, Health: map[string]int{}}
			probeHTTP(c, srv.URL, &res)
			if got, ok := res.Health[srv.URL]; !ok || got != tc.want {
				t.Fatalf("health = %d (recorded %v), want %d; body %q", got, ok, tc.want, res.Bodies[srv.URL+"/health"])
			}
			if b := res.Bodies[srv.URL+"/health"]; !strings.Contains(b, tc.bodyHint) {
				t.Fatalf("health body %q does not contain %q", b, tc.bodyHint)
			}
		})
	}
}

func TestProbeTLSConfigFloor(t *testing.T) {
	_, pemBytes := selfSignedLikeAdminInit(t)
	tc, err := probeTLSConfig(probeCase(t, pemBytes))
	if err != nil {
		t.Fatal(err)
	}
	if tc.InsecureSkipVerify || tc.MinVersion != tls.VersionTLS12 || tc.RootCAs == nil || tc.ServerName != "localhost" {
		t.Fatalf("probe TLS config = skip %v, min %x, roots %v, name %q", tc.InsecureSkipVerify, tc.MinVersion, tc.RootCAs != nil, tc.ServerName)
	}
}
