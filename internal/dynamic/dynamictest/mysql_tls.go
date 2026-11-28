package dynamictest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ServeMySQLTLS starts a loopback server that speaks just enough of the MySQL protocol
// to offer TLS, complete the handshake (self-signed certificate: connect with
// tls=skip-verify) and accept any credentials, then answers a hostile reply.
//
// netutil.MySQLGuardDialer steps aside once the client asks for TLS, so a test that
// needs the driver to see a malformed reply the guard would refuse in plaintext has to
// negotiate TLS first. reply is the raw packet bytes sent in answer to every command
// after the handshake (with the sequence numbers of a plaintext conversation: the first
// reply is seq 1); when stage is "auth" it answers the handshake response instead, with
// the sequence number rewritten from 2 to 3.
//
// handshakes counts completed TLS handshakes: a test asserts it is non-zero so a case
// that never reached the TLS path cannot pass for one that did. Each connection is
// dropped after 3 s.
func ServeMySQLTLS(t testing.TB, stage string, reply []byte) (host, port string, handshakes *atomic.Int32) {
	t.Helper()
	cfg := selfSignedTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener (environment): %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	handshakes = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				serveMySQLTLSConn(c, cfg, stage, reply, handshakes)
			}()
		}
	}()
	host, port, _ = net.SplitHostPort(ln.Addr().String())
	return host, port, handshakes
}

func selfSignedTLS(t testing.TB) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hostile.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
}

func myPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

func readMyPacket(r io.Reader) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, r, int64(h[0])|int64(h[1])<<8|int64(h[2])<<16)
	return err
}

// tlsGreeting is a protocol-10 greeting advertising CLIENT_SSL and mysql_native_password.
func tlsGreeting() []byte {
	const caps = 0x00000001 | 0x00000004 | 0x00000200 | 0x00000800 | 0x00002000 | 0x00008000 | 0x00020000 | 0x00080000 | 0x00200000
	p := []byte{0x0a}
	p = append(p, []byte("8.0.40")...)
	p = append(p, 0, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0)
	p = binary.LittleEndian.AppendUint16(p, caps&0xffff)
	p = append(p, 0x2d)
	p = binary.LittleEndian.AppendUint16(p, 2)
	p = binary.LittleEndian.AppendUint16(p, caps>>16)
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0)
	p = append(p, []byte("mysql_native_password")...)
	return myPacket(0, append(p, 0))
}

func serveMySQLTLSConn(c net.Conn, cfg *tls.Config, stage string, reply []byte, handshakes *atomic.Int32) {
	if _, err := c.Write(tlsGreeting()); err != nil {
		return
	}
	if readMyPacket(c) != nil { // SSLRequest, still plaintext
		return
	}
	sc := tls.Server(c, cfg)
	if sc.Handshake() != nil {
		return
	}
	handshakes.Add(1)
	r := bufio.NewReader(sc)
	if readMyPacket(r) != nil { // handshake response, seq 2
		return
	}
	if stage == "auth" {
		f := append([]byte(nil), reply...)
		if len(f) > 3 {
			f[3] = 3
		}
		_, _ = sc.Write(f)
		return
	}
	if _, err := sc.Write(myPacket(3, []byte{0, 0, 0, 2, 0, 0, 0})); err != nil { // OK
		return
	}
	for {
		if readMyPacket(r) != nil {
			return
		}
		if _, err := sc.Write(reply); err != nil {
			return
		}
	}
}
