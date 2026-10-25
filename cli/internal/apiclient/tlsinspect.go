package apiclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// ErrNotHTTPS is returned by InspectTLS for a server URL that does not use TLS.
var ErrNotHTTPS = errors.New("server URL is not https")

// CertInfo is the part of an X.509 certificate `keyorix doctor` shows.
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	IsCA      bool      `json:"is_ca"`
}

// TLSReport is what a TLS handshake with the server showed.
type TLSReport struct {
	Host string `json:"host"`
	// TrustSource names the roots the chain was checked against: "system roots" or the
	// --ca-file path.
	TrustSource string `json:"trust_source"`
	// Verified is true when the chain verifies against TrustSource for Host.
	Verified bool `json:"verified"`
	// VerifyError is why it did not (empty when Verified).
	VerifyError string `json:"verify_error,omitempty"`
	// TLSVersion is the negotiated protocol version, when the handshake completed.
	TLSVersion string `json:"tls_version,omitempty"`
	// KeyExchange is the key-exchange group the handshake negotiated (for example
	// "X25519MLKEM768"), when the handshake completed and used an ECDHE group.
	KeyExchange string `json:"key_exchange,omitempty"`
	// PostQuantumKeyExchange is true when KeyExchange is a hybrid with an ML-KEM
	// component. It says nothing about the certificate chain, which is classical.
	PostQuantumKeyExchange bool `json:"post_quantum_key_exchange,omitempty"`
	// Chain is the server's chain, leaf first. After a verification failure it is the
	// unverified chain the server presented, when the error carries it.
	Chain []CertInfo `json:"chain,omitempty"`
}

// InspectTLS performs a TLS handshake with the server named by serverURL and reports
// what it found. It sends no HTTP request and never skips verification: a certificate
// that does not verify is reported through TLSReport.Verified/VerifyError (with the
// chain taken from the verification error), not trusted. caFile, when non-empty,
// replaces the system roots exactly as it does for API calls. The returned error is
// for problems that are not certificate verdicts (not https, cannot connect).
func InspectTLS(ctx context.Context, serverURL, caFile string) (TLSReport, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return TLSReport{}, fmt.Errorf("invalid server URL %q", serverURL)
	}
	if u.Scheme != "https" {
		return TLSReport{}, ErrNotHTTPS
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	rep := TLSReport{Host: net.JoinHostPort(host, port), TrustSource: "system roots"}

	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := LoadCAPool(caFile)
		if err != nil {
			return rep, fmt.Errorf("CA file %s: %w", caFile, err)
		}
		cfg.RootCAs = pool
		rep.TrustSource = caFile
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	conn, err := d.DialContext(dialCtx, "tcp", rep.Host)
	if err == nil {
		defer func() { _ = conn.Close() }()
		st := conn.(*tls.Conn).ConnectionState()
		rep.Verified = true
		rep.TLSVersion = tls.VersionName(st.Version)
		rep.KeyExchange, rep.PostQuantumKeyExchange = keyExchangeName(st.CurveID)
		if len(st.VerifiedChains) > 0 {
			rep.Chain = certInfos(st.VerifiedChains[0])
		} else {
			rep.Chain = certInfos(st.PeerCertificates)
		}
		return rep, nil
	}

	// A certificate verdict: report it, with whatever chain the error carries.
	var (
		verifyErr   *tls.CertificateVerificationError
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		invalid     x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &verifyErr):
		rep.VerifyError = verifyErr.Err.Error()
		rep.Chain = certInfos(verifyErr.UnverifiedCertificates)
	case errors.As(err, &unknownAuth):
		rep.VerifyError = unknownAuth.Error()
		rep.Chain = certInfos([]*x509.Certificate{unknownAuth.Cert})
	case errors.As(err, &hostErr):
		rep.VerifyError = hostErr.Error()
		rep.Chain = certInfos([]*x509.Certificate{hostErr.Certificate})
	case errors.As(err, &invalid):
		rep.VerifyError = invalid.Error()
		rep.Chain = certInfos([]*x509.Certificate{invalid.Cert})
	default:
		return rep, err
	}
	return rep, nil
}

// keyExchangeName names a negotiated group and says whether it is an ML-KEM hybrid. An
// unknown group is named by its code point; a zero id (no ECDHE group) is "".
func keyExchangeName(id tls.CurveID) (name string, postQuantum bool) {
	switch id {
	case 0:
		return "", false
	case tls.X25519MLKEM768:
		return "X25519MLKEM768", true
	case tls.SecP256r1MLKEM768:
		return "SecP256r1MLKEM768", true
	case tls.SecP384r1MLKEM1024:
		return "SecP384r1MLKEM1024", true
	case tls.X25519:
		return "X25519", false
	case tls.CurveP256:
		return "P-256", false
	case tls.CurveP384:
		return "P-384", false
	case tls.CurveP521:
		return "P-521", false
	default:
		return fmt.Sprintf("group-0x%04x", uint16(id)), false
	}
}

func certInfos(certs []*x509.Certificate) []CertInfo {
	out := make([]CertInfo, 0, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		out = append(out, CertInfo{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
			DNSNames:  c.DNSNames,
			IsCA:      c.IsCA,
		})
	}
	return out
}
