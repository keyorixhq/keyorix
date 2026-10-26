package cryptoinventory

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxCertFileBytes bounds how much of a configured certificate file is read.
const maxCertFileBytes = 1 << 20

// LoadCertificateInfo parses the first CERTIFICATE block of a PEM file and returns
// its public metadata. Only CERTIFICATE blocks are ever decoded: a private key
// stored in the same file (a common combined-PEM layout) is skipped without being
// parsed, and errors never echo file content.
func LoadCertificateInfo(path string) (CertInfo, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured TLS certificate path (server.*.tls.cert_file)
	if err != nil {
		return CertInfo{}, fmt.Errorf("open certificate: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCertFileBytes))
	if err != nil {
		return CertInfo{}, fmt.Errorf("read certificate: %w", err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return CertInfo{}, errors.New("no CERTIFICATE block found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CertInfo{}, errors.New("certificate block is not a valid X.509 certificate")
		}
		return certInfo(cert), nil
	}
}

func certInfo(c *x509.Certificate) CertInfo {
	ci := CertInfo{
		SubjectName:        c.Subject.String(),
		IssuerName:         c.Issuer.String(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
	}
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyAlgorithm, ci.KeySizeBits = fmt.Sprintf("RSA-%d", pub.N.BitLen()), pub.N.BitLen()
	case *ecdsa.PublicKey:
		ci.Curve = pub.Curve.Params().Name
		ci.KeyAlgorithm, ci.KeySizeBits = "ECDSA-"+strings.ReplaceAll(ci.Curve, "-", ""), pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		ci.KeyAlgorithm, ci.KeySizeBits, ci.Curve = "Ed25519", 256, "Ed25519"
	default:
		ci.KeyAlgorithm = c.PublicKeyAlgorithm.String()
	}
	return ci
}
