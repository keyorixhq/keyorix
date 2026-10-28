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
	"strings"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// maxCertFileBytes bounds how much of a configured certificate file is read.
const maxCertFileBytes = 1 << 20

// LoadCertificateInfo parses the first CERTIFICATE block of a PEM file and returns
// its public metadata. Only CERTIFICATE blocks are ever decoded: a private key
// stored in the same file (a common combined-PEM layout) is skipped without being
// parsed, and errors never echo file content.
func LoadCertificateInfo(path string) (CertInfo, error) {
	infos, err := LoadCertificates(path, 1)
	if err != nil {
		return CertInfo{}, err
	}
	return infos[0], nil
}

// LoadCertificates parses up to limit CERTIFICATE blocks of a PEM file (a CA bundle
// holds several) with the same guarantees as LoadCertificateInfo: other block
// types are skipped unparsed and errors never echo file content. It fails when
// the file has no certificate or when any selected block is not valid X.509.
func LoadCertificates(path string, limit int) ([]CertInfo, error) {
	// Operator-configured certificate path (tls.cert_file, database ssl_root_cert /
	// sslcert). OpenRegular opens non-blocking and refuses a FIFO or device, so a
	// mis-pointed path cannot hang the inventory. Symlinks to a regular file are followed.
	f, _, err := secretenv.OpenRegular(path, 0)
	if err != nil {
		return nil, fmt.Errorf("open certificate: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCertFileBytes))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return certificatesFromPEM(data, limit)
}

func certificatesFromPEM(data []byte, limit int) ([]CertInfo, error) {
	var out []CertInfo
	for len(out) < limit {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("certificate block is not a valid X.509 certificate")
		}
		out = append(out, certInfo(cert))
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE block found")
	}
	return out, nil
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
