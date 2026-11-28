package demolan_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/configs"
)

// These tests cover the LAN demo installer (install.sh) and its openssl-only PKI helper
// (pki.sh) without a server and without systemd: the scripts' decisions (argument and
// existing-install refusals, address detection), the certificates they issue (names,
// constraints, key modes, validity), and the renewal threshold. The real install on a box is
// run by hand (docs/demo/LAN-TLS.md); what these cannot show is named in each test.

// ── helpers ────────────────────────────────────────────────────────────────

func run(t *testing.T, env []string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		t.Fatalf("%s %v: %v", name, args, err)
		return "", -1
	}
}

func needOpenssl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return c
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func days(c *x509.Certificate) float64 { return c.NotAfter.Sub(c.NotBefore).Hours() / 24 }

type pkiDirs struct{ ca, leaf string }

func newPKIDirs(t *testing.T) pkiDirs {
	root := t.TempDir()
	return pkiDirs{ca: filepath.Join(root, "pki", "ca"), leaf: filepath.Join(root, "pki", "leaf")}
}

// pki runs pki.sh <cmd> with the dirs and extra arguments.
func (d pkiDirs) pki(t *testing.T, env []string, cmd string, extra ...string) (string, int) {
	t.Helper()
	args := append([]string{"pki.sh", cmd, "--ca-dir", d.ca, "--leaf-dir", d.leaf}, extra...)
	return run(t, env, "bash", args...)
}

// Documentation-range addresses only (RFC 5737): no real or lab address belongs in a repo.
var boxNames = []string{"--ip", "192.0.2.10", "--dns", "demo-box", "--dns", "demo-box.lan"}

func initPKI(t *testing.T, d pkiDirs, env []string, extra ...string) {
	t.Helper()
	out, code := d.pki(t, env, "init", append(append([]string{}, boxNames...), extra...)...)
	if code != 0 {
		t.Fatalf("pki.sh init failed (%d):\n%s", code, out)
	}
}

// ── scripts parse and lint ─────────────────────────────────────────────────

func TestScriptsParse(t *testing.T) {
	needOpenssl(t)
	for _, f := range []string{"install.sh", "pki.sh"} {
		if out, code := run(t, nil, "bash", "-n", f); code != 0 {
			t.Errorf("bash -n %s: %s", f, out)
		}
		t.Run("shellcheck/"+f, func(t *testing.T) {
			if _, err := exec.LookPath("shellcheck"); err != nil {
				t.Skip("shellcheck is not installed")
			}
			if out, code := run(t, nil, "shellcheck", f); code != 0 {
				t.Errorf("shellcheck %s:\n%s", f, out)
			}
		})
	}
}

// ── no lab address in any committed file ───────────────────────────────────

var ipv4 = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

// Loopback, the wildcard bind and the RFC 5737 documentation ranges are the only literal
// addresses these files may contain. The box's own address is always detected at run time.
var allowedIP = []string{"127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.", "192.0.2.", "198.51.100.", "203.0.113."}

// The lab host's name is assembled so that this file does not contain it either.
var labHost = "pve" + "01"

func TestNoLabAddressInCommittedFiles(t *testing.T) {
	files, _ := filepath.Glob("*")
	docs, _ := filepath.Glob("../../docs/demo/LAN-TLS.md")
	frags, _ := filepath.Glob("../../changelog.d/*demo-lan*")
	files = append(files, docs...)
	files = append(files, frags...)
	if len(docs) == 0 {
		t.Error("docs/demo/LAN-TLS.md is missing")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for n, line := range strings.Split(string(raw), "\n") {
			for _, ip := range ipv4.FindAllString(line, -1) {
				ok := false
				for _, a := range allowedIP {
					if ip == a || (strings.HasSuffix(a, ".") && strings.HasPrefix(ip, a)) {
						ok = true
					}
				}
				if !ok {
					t.Errorf("%s:%d: literal address %s (only loopback and RFC 5737 documentation ranges are allowed)", f, n+1, ip)
				}
			}
			if strings.Contains(line, labHost) {
				t.Errorf("%s:%d: names a lab host", f, n+1)
			}
		}
	}
}

// ── the CA and the certificate ─────────────────────────────────────────────

func TestPKI_CAAndLeaf(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)

	// Key files: 0600; the CA key lives in a 0700 directory.
	if m := perm(t, filepath.Join(d.ca, "ca.key")); m != 0o600 {
		t.Errorf("ca.key mode %o, want 600", m)
	}
	if m := perm(t, filepath.Join(d.leaf, "server.key")); m != 0o600 {
		t.Errorf("server.key mode %o, want 600", m)
	}
	if m := perm(t, d.ca); m != 0o700 {
		t.Errorf("CA directory mode %o, want 700", m)
	}

	ca := readCert(t, filepath.Join(d.ca, "ca.crt"))
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Errorf("CA must be CA:TRUE, pathlen:0 (IsCA=%v MaxPathLen=%d)", ca.IsCA, ca.MaxPathLen)
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA lacks keyCertSign")
	}
	if pub, ok := ca.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("CA key is not ECDSA P-256: %T", ca.PublicKey)
	}
	if dd := days(ca); dd < 3649 || dd > 3651 {
		t.Errorf("CA validity %.1f days, want about 3650", dd)
	}

	// nameConstraints: critical, exactly the box's names plus localhost / 127.0.0.1.
	if !ca.PermittedDNSDomainsCritical {
		t.Error("nameConstraints must be critical")
	}
	gotDNS := append([]string(nil), ca.PermittedDNSDomains...)
	sort.Strings(gotDNS)
	if want := []string{"demo-box", "demo-box.lan", "localhost"}; strings.Join(gotDNS, ",") != strings.Join(want, ",") {
		t.Errorf("permitted DNS %v, want %v", gotDNS, want)
	}
	var gotIPs []string
	for _, r := range ca.PermittedIPRanges {
		gotIPs = append(gotIPs, r.String())
	}
	sort.Strings(gotIPs)
	if want := []string{"127.0.0.1/32", "192.0.2.10/32"}; strings.Join(gotIPs, ",") != strings.Join(want, ",") {
		t.Errorf("permitted IP ranges %v, want %v", gotIPs, want)
	}
	if len(ca.ExcludedDNSDomains)+len(ca.ExcludedIPRanges) != 0 {
		t.Error("unexpected excluded ranges")
	}
	// No e-mail address or URI is permitted, and the CA itself is limited to serverAuth.
	if strings.Join(ca.PermittedEmailAddresses, ",") != ".invalid" || strings.Join(ca.PermittedURIDomains, ",") != ".invalid" {
		t.Errorf("permitted e-mail %v / URI %v, want only .invalid", ca.PermittedEmailAddresses, ca.PermittedURIDomains)
	}
	if len(ca.ExtKeyUsage) != 1 || ca.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("CA ExtKeyUsage %v, want [serverAuth]", ca.ExtKeyUsage)
	}

	leaf := readCert(t, filepath.Join(d.leaf, "server.crt"))
	if leaf.IsCA {
		t.Error("leaf must not be a CA")
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("leaf key is not ECDSA P-256: %T", leaf.PublicKey)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("leaf ExtKeyUsage %v, want [serverAuth]", leaf.ExtKeyUsage)
	}
	if dd := days(leaf); dd > 825 || dd < 800 {
		t.Errorf("leaf validity %.1f days, want <= 825 (Apple/Chrome cap) and about 820", dd)
	}
	gotSAN := append([]string(nil), leaf.DNSNames...)
	sort.Strings(gotSAN)
	if want := []string{"demo-box", "demo-box.lan", "localhost"}; strings.Join(gotSAN, ",") != strings.Join(want, ",") {
		t.Errorf("leaf DNS SANs %v, want %v", gotSAN, want)
	}
	var sanIPs []string
	for _, ip := range leaf.IPAddresses {
		sanIPs = append(sanIPs, ip.String())
	}
	sort.Strings(sanIPs)
	if want := []string{"127.0.0.1", "192.0.2.10"}; strings.Join(sanIPs, ",") != strings.Join(want, ",") {
		t.Errorf("leaf IP SANs %v, want %v", sanIPs, want)
	}

	// The chain verifies for every name the box answers to, and for no other.
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"demo-box", "demo-box.lan", "localhost", "192.0.2.10", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("verify for %s: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("the certificate must not verify for a name that is not the box's")
	}
	if out, code := run(t, nil, "openssl", "verify", "-CAfile", filepath.Join(d.ca, "ca.crt"), filepath.Join(d.leaf, "server.crt")); code != 0 {
		t.Errorf("openssl verify: %s", out)
	}
}

// signWithCA has the local CA's own key sign a certificate with the given extensions (what
// anyone holding ca.key could do) and returns it and its path.
func signWithCA(t *testing.T, d pkiDirs, extensions string) (*x509.Certificate, string) {
	t.Helper()
	w := t.TempDir()
	ext := filepath.Join(w, "ext.cnf")
	if err := os.WriteFile(ext, []byte(extensions), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := [][]string{
		{"ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", filepath.Join(w, "k.pem")},
		{"req", "-new", "-key", filepath.Join(w, "k.pem"), "-subj", "/CN=signed-by-the-demo-ca", "-out", filepath.Join(w, "k.csr")},
		{"x509", "-req", "-in", filepath.Join(w, "k.csr"), "-CA", filepath.Join(d.ca, "ca.crt"), "-CAkey", filepath.Join(d.ca, "ca.key"),
			"-set_serial", "0x1234", "-days", "30", "-extfile", ext, "-out", filepath.Join(w, "c.crt")},
	}
	for _, s := range steps {
		if out, code := run(t, nil, "openssl", s...); code != 0 {
			t.Fatalf("openssl %v: %s", s, out)
		}
	}
	return readCert(t, filepath.Join(w, "c.crt")), filepath.Join(w, "c.crt")
}

// The point of the constraints: even the CA's own key cannot make a certificate that a client
// which trusts the CA would accept for another site, another address, an e-mail address or a
// URI, or for a purpose other than a TLS server. Each case is checked by Go's verifier and, for
// the names, by `openssl verify`.
func TestPKI_CAConstraintRejectsOtherNames(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)
	roots := x509.NewCertPool()
	roots.AddCert(readCert(t, filepath.Join(d.ca, "ca.crt")))
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for _, tc := range []struct {
		name, ext, dnsName string
		usages             []x509.ExtKeyUsage
	}{
		{"another site", "subjectAltName = DNS:evil.example\nextendedKeyUsage = serverAuth\n", "evil.example", serverAuth},
		{"a neighbour's address", "subjectAltName = IP:192.0.2.11\nextendedKeyUsage = serverAuth\n", "192.0.2.11", serverAuth},
		{"another network", "subjectAltName = IP:198.51.100.10\nextendedKeyUsage = serverAuth\n", "198.51.100.10", serverAuth},
		{"an e-mail address", "subjectAltName = DNS:demo-box, email:ceo@evil.example\nextendedKeyUsage = serverAuth\n", "demo-box", serverAuth},
		{"a URI", "subjectAltName = DNS:demo-box, URI:https://evil.example/\nextendedKeyUsage = serverAuth\n", "demo-box", serverAuth},
		{"code signing for the box's own name", "subjectAltName = DNS:demo-box\nextendedKeyUsage = codeSigning\n", "", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
		{"a TLS client for the box's own name", "subjectAltName = DNS:demo-box\nextendedKeyUsage = clientAuth\n", "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, path := signWithCA(t, d, tc.ext)
			if _, err := c.Verify(x509.VerifyOptions{Roots: roots, DNSName: tc.dnsName, KeyUsages: tc.usages}); err == nil {
				t.Errorf("a certificate for %s signed by the local CA verified", tc.name)
			}
			if tc.usages[0] != x509.ExtKeyUsageServerAuth {
				return // `openssl verify` without -purpose does not check extendedKeyUsage
			}
			if out, code := run(t, nil, "openssl", "verify", "-CAfile", filepath.Join(d.ca, "ca.crt"), path); code == 0 {
				t.Errorf("openssl verify accepted the out-of-constraint certificate: %s", out)
			}
		})
	}

	// What a DNS name constraint cannot express (RFC 5280 name constraints): it also permits every name
	// below it. pki.sh's header, the installer's summary and docs/demo/LAN-TLS.md say so; this
	// pins the behaviour they describe, so the text cannot drift from it.
	c, _ := signWithCA(t, d, "subjectAltName = DNS:x.demo-box.lan\nextendedKeyUsage = serverAuth\n")
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, DNSName: "x.demo-box.lan", KeyUsages: serverAuth}); err != nil {
		t.Errorf("a name below a permitted one no longer verifies (%v): update the documented limitation", err)
	}
	for _, f := range []string{"pki.sh", "install.sh", "../../docs/demo/LAN-TLS.md"} {
		if !strings.Contains(strings.ToLower(string(readBytes(t, f))), "below") {
			t.Errorf("%s no longer states that a DNS constraint also permits the names below it", f)
		}
	}
	if strings.Contains(string(readBytes(t, "pki.sh")), "trusts it for nothing else") {
		t.Error(`pki.sh claims a client "trusts it for nothing else", which the subdomain case above disproves`)
	}
}

func TestPKI_InitIsIdempotent(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)
	caBefore, leafBefore, keyBefore := readBytes(t, filepath.Join(d.ca, "ca.crt")), readBytes(t, filepath.Join(d.leaf, "server.crt")), readBytes(t, filepath.Join(d.leaf, "server.key"))
	initPKI(t, d, nil)
	if !bytes.Equal(caBefore, readBytes(t, filepath.Join(d.ca, "ca.crt"))) {
		t.Error("a second init replaced the CA")
	}
	if !bytes.Equal(leafBefore, readBytes(t, filepath.Join(d.leaf, "server.crt"))) || !bytes.Equal(keyBefore, readBytes(t, filepath.Join(d.leaf, "server.key"))) {
		t.Error("a second init replaced a valid certificate")
	}
}

// ── the renewal threshold ──────────────────────────────────────────────────

func TestPKI_RenewalThreshold(t *testing.T) {
	needOpenssl(t)
	for _, tc := range []struct {
		leafDays string
		due      bool
	}{
		{"29", true}, {"31", false}, {"100", false}, {"820", false},
	} {
		t.Run(tc.leafDays+"d", func(t *testing.T) {
			d := newPKIDirs(t)
			initPKI(t, d, []string{"KEYORIX_LAN_LEAF_DAYS=" + tc.leafDays})
			out, code := d.pki(t, nil, "check")
			if tc.due && (code != 1 || !strings.Contains(out, "fewer than 30 days")) {
				t.Errorf("a %s-day certificate must need renewal (exit %d): %s", tc.leafDays, code, out)
			}
			if !tc.due && code != 0 {
				t.Errorf("a %s-day certificate must not need renewal (exit %d): %s", tc.leafDays, code, out)
			}
		})
	}
}

func TestPKI_RenewReplacesOnlyTheLeafAndKeepsTheOldOne(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, []string{"KEYORIX_LAN_LEAF_DAYS=20"})
	caCrt, caKey := readBytes(t, filepath.Join(d.ca, "ca.crt")), readBytes(t, filepath.Join(d.ca, "ca.key"))
	oldCrt, oldKey := readBytes(t, filepath.Join(d.leaf, "server.crt")), readBytes(t, filepath.Join(d.leaf, "server.key"))
	oldCert := readCert(t, filepath.Join(d.leaf, "server.crt"))

	out, code := d.pki(t, nil, "renew")
	if code != 0 || !strings.Contains(out, "renewed") {
		t.Fatalf("renew (exit %d): %s", code, out)
	}
	newCert := readCert(t, filepath.Join(d.leaf, "server.crt"))
	if newCert.SerialNumber.Cmp(oldCert.SerialNumber) == 0 {
		t.Error("renew kept the old certificate")
	}
	if dd := days(newCert); dd < 800 || dd > 825 {
		t.Errorf("renewed certificate validity %.1f days", dd)
	}
	if !bytes.Equal(caCrt, readBytes(t, filepath.Join(d.ca, "ca.crt"))) || !bytes.Equal(caKey, readBytes(t, filepath.Join(d.ca, "ca.key"))) {
		t.Error("a renewal changed the CA: clients would have to trust again")
	}
	if m := perm(t, filepath.Join(d.leaf, "server.key")); m != 0o600 {
		t.Errorf("renewed server.key mode %o, want 600", m)
	}
	olds, _ := filepath.Glob(filepath.Join(d.leaf, "old", "*", "server.crt"))
	if len(olds) != 1 || !bytes.Equal(readBytes(t, olds[0]), oldCrt) {
		t.Errorf("the replaced certificate was not kept under old/: %v", olds)
	}
	oldKeys, _ := filepath.Glob(filepath.Join(d.leaf, "old", "*", "server.key"))
	if len(oldKeys) != 1 || !bytes.Equal(readBytes(t, oldKeys[0]), oldKey) {
		t.Errorf("the replaced key was not kept under old/: %v", oldKeys)
	}
	// Same names after renewal: SAN set is unchanged.
	if strings.Join(newCert.DNSNames, ",") != strings.Join(oldCert.DNSNames, ",") || len(newCert.IPAddresses) != len(oldCert.IPAddresses) {
		t.Error("renewal changed the certificate's names")
	}

	// A certificate that is fine is left alone.
	before := readBytes(t, filepath.Join(d.leaf, "server.crt"))
	out, code = d.pki(t, nil, "renew")
	if code != 0 || !strings.Contains(out, "certificate ok") {
		t.Errorf("second renew (exit %d): %s", code, out)
	}
	if !bytes.Equal(before, readBytes(t, filepath.Join(d.leaf, "server.crt"))) {
		t.Error("renew replaced a certificate with more than 30 days left")
	}
}

func TestPKI_RenewReissuesAMismatchedKey(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)
	other := newPKIDirs(t)
	initPKI(t, other, nil)
	// A key that does not belong to the certificate (a partial copy, an interrupted rotation).
	if err := os.WriteFile(filepath.Join(d.leaf, "server.key"), readBytes(t, filepath.Join(other.leaf, "server.key")), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := d.pki(t, nil, "check"); code != 1 || !strings.Contains(out, "do not match") {
		t.Errorf("check must flag the mismatch (exit %d): %s", code, out)
	}
	if out, code := d.pki(t, nil, "renew"); code != 0 || !strings.Contains(out, "renewed") {
		t.Errorf("renew (exit %d): %s", code, out)
	}
	if out, code := d.pki(t, nil, "check"); code != 0 {
		t.Errorf("check after renew (exit %d): %s", code, out)
	}
}

// ── names: a new address needs an explicit new CA ──────────────────────────

func TestPKI_NewAddressNeedsNewCA(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)
	caBefore := readBytes(t, filepath.Join(d.ca, "ca.crt"))

	out, code := d.pki(t, nil, "init", "--ip", "192.0.2.77", "--dns", "demo-box")
	if code == 0 || !strings.Contains(out, "--new-ca") {
		t.Fatalf("a new address must be refused without --new-ca (exit %d): %s", code, out)
	}
	if !bytes.Equal(caBefore, readBytes(t, filepath.Join(d.ca, "ca.crt"))) {
		t.Error("the refused init changed the CA")
	}

	if out, code = d.pki(t, nil, "init", "--ip", "192.0.2.77", "--dns", "demo-box", "--new-ca"); code != 0 {
		t.Fatalf("init --new-ca (exit %d): %s", code, out)
	}
	if bytes.Equal(caBefore, readBytes(t, filepath.Join(d.ca, "ca.crt"))) {
		t.Error("--new-ca kept the old CA")
	}
	oldCAs, _ := filepath.Glob(filepath.Join(d.ca, "old", "*", "ca.crt"))
	oldKeys, _ := filepath.Glob(filepath.Join(d.ca, "old", "*", "ca.key"))
	if len(oldCAs) != 1 || len(oldKeys) != 1 || !bytes.Equal(readBytes(t, oldCAs[0]), caBefore) {
		t.Errorf("the old CA was not kept: %v %v", oldCAs, oldKeys)
	}
	leaf := readCert(t, filepath.Join(d.leaf, "server.crt"))
	if !containsIP(leaf.IPAddresses, "192.0.2.77") {
		t.Errorf("new certificate lacks the new address: %v", leaf.IPAddresses)
	}
}

func containsIP(ips []net.IP, want string) bool {
	for _, ip := range ips {
		if ip.Equal(net.ParseIP(want)) {
			return true
		}
	}
	return false
}

// A narrower name list under the same CA re-issues the certificate and keeps the CA.
func TestPKI_FewerNamesKeepTheCA(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)
	caBefore := readBytes(t, filepath.Join(d.ca, "ca.crt"))
	if out, code := d.pki(t, nil, "init", "--ip", "192.0.2.10"); code != 0 {
		t.Fatalf("init (exit %d): %s", code, out)
	}
	if !bytes.Equal(caBefore, readBytes(t, filepath.Join(d.ca, "ca.crt"))) {
		t.Error("a name subset replaced the CA")
	}
	leaf := readCert(t, filepath.Join(d.leaf, "server.crt"))
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
		t.Errorf("DNS SANs %v, want only localhost", leaf.DNSNames)
	}
}

func TestPKI_RejectsBadInput(t *testing.T) {
	needOpenssl(t)
	for name, args := range map[string][]string{
		"config injection in a name": {"--ip", "192.0.2.10", "--dns", "x\n[v3_ca]\nbasicConstraints=CA:TRUE"},
		"space in a name":            {"--ip", "192.0.2.10", "--dns", "bad name"},
		"octet over 255":             {"--ip", "192.0.2.256"},
		"not an address":             {"--ip", "box"},
		"no address":                 {"--dns", "demo-box"},
	} {
		t.Run(name, func(t *testing.T) {
			d := newPKIDirs(t)
			if out, code := d.pki(t, nil, "init", args...); code == 0 {
				t.Errorf("accepted: %s", out)
			}
			if _, err := os.Stat(filepath.Join(d.ca, "ca.key")); err == nil {
				t.Error("a CA was created for rejected input")
			}
		})
	}
	d := newPKIDirs(t)
	if out, code := d.pki(t, nil, "renew"); code == 0 || !strings.Contains(out, "no CA") {
		t.Errorf("renew without a CA (exit %d): %s", code, out)
	}
}

// ── install.sh decisions that need no root and no systemd ──────────────────

func fakeELF(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), append([]byte{0x7f, 'E', 'L', 'F'}, "not a real binary"...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInstall_ArgumentAndBinaryErrors(t *testing.T) {
	needOpenssl(t)
	missing := t.TempDir()
	fakeELF(t, missing, "keyorix", "keyorix-server") // totpgen absent
	notELF := t.TempDir()
	for _, n := range []string{"keyorix", "keyorix-server", "totpgen"} {
		if err := os.WriteFile(filepath.Join(notELF, n), []byte("MZ or Mach-O, not ELF"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "--bin-dir is required"},
		{"unknown flag", []string{"--bogus"}, "unknown argument"},
		{"value missing", []string{"--bin-dir"}, "needs a value"},
		{"bin-dir not a directory", []string{"--bin-dir", filepath.Join(missing, "nope")}, "not a directory"},
		{"relative dir", []string{"--bin-dir", missing, "--dir", "relative/dir"}, "absolute path"},
		{"dir with a space", []string{"--bin-dir", missing, "--dir", "/opt/a b"}, "absolute path"},
		{"dir under /home", []string{"--bin-dir", missing, "--dir", "/home/demo/keyorix"}, "must not be under /home"},
		{"dir is /root", []string{"--bin-dir", missing, "--dir", "/root"}, "must not be under /home"},
		{"port zero", []string{"--bin-dir", missing, "--port", "0"}, "--port must be"},
		{"port not a number", []string{"--bin-dir", missing, "--port", "http"}, "--port must be"},
		{"missing binary", []string{"--bin-dir", missing}, "missing binary"},
		{"not a linux binary", []string{"--bin-dir", notELF}, "not a Linux (ELF) binary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := run(t, nil, "bash", append([]string{"install.sh"}, tc.args...)...)
			if code == 0 || !strings.Contains(out, tc.want) {
				t.Errorf("exit %d, want failure containing %q:\n%s", code, tc.want, out)
			}
		})
	}
}

func TestInstall_RefusesAnExistingDatabaseAndTouchesNothing(t *testing.T) {
	needOpenssl(t)
	bins := t.TempDir()
	fakeELF(t, bins, "keyorix", "keyorix-server", "totpgen")
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "state", "keyorix.db")
	if err := os.WriteFile(db, []byte("somebody's data"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, nil, "bash", "install.sh", "--bin-dir", bins, "--dir", dir)
	if code == 0 || !strings.Contains(out, "keyorix.db already exists") || !strings.Contains(out, "--reuse") {
		t.Fatalf("exit %d, want a refusal naming keyorix.db and --reuse:\n%s", code, out)
	}
	if got := readBytes(t, db); string(got) != "somebody's data" {
		t.Errorf("the database was modified: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "state" {
		t.Errorf("the refused install created files in %s: %v", dir, entries)
	}
}

func TestInstall_ReuseNeedsAFinishedInstall(t *testing.T) {
	needOpenssl(t)
	bins := t.TempDir()
	fakeELF(t, bins, "keyorix", "keyorix-server", "totpgen")
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state", "keyorix.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, nil, "bash", "install.sh", "--bin-dir", bins, "--dir", dir, "--reuse")
	if code == 0 || !strings.Contains(out, "not a finished install") {
		t.Errorf("exit %d, want --reuse to refuse an unfinished install:\n%s", code, out)
	}
}

// On a box that is root with systemd this would install for real: only run where it cannot.
func TestInstall_RefusesWithoutSystemdOrRoot(t *testing.T) {
	needOpenssl(t)
	if _, err := os.Stat("/run/systemd/system"); err == nil && os.Geteuid() == 0 {
		t.Skip("root on a systemd host: this test would run the real installer")
	}
	bins := t.TempDir()
	fakeELF(t, bins, "keyorix", "keyorix-server", "totpgen")
	dir := filepath.Join(t.TempDir(), "demo")
	out, code := run(t, nil, "bash", "install.sh", "--bin-dir", bins, "--dir", dir)
	if code == 0 || !(strings.Contains(out, "systemd") || strings.Contains(out, "must be run as root")) {
		t.Errorf("exit %d, want a systemd/root refusal:\n%s", code, out)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the refused install created its directory")
	}
}

// ── address detection ──────────────────────────────────────────────────────

func stubDir(t *testing.T, scripts map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(d, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func detect(t *testing.T, stubs map[string]string) string {
	t.Helper()
	path := stubDir(t, stubs) + string(os.PathListSeparator) + os.Getenv("PATH")
	out, code := run(t, []string{"PATH=" + path}, "bash", "-c", `source ./install.sh; detect_ip`)
	if code != 0 {
		t.Fatalf("detect_ip exit %d: %s", code, out)
	}
	return strings.TrimSpace(out)
}

func TestInstall_DetectsTheAddressAtRunTime(t *testing.T) {
	needOpenssl(t)
	// `ip route get` gives the source address of the route out.
	got := detect(t, map[string]string{
		"ip": `echo "192.0.2.1 via 198.51.100.1 dev eth0 src 198.51.100.7 uid 0"`,
	})
	if got != "198.51.100.7" {
		t.Errorf("route source: got %q", got)
	}
	// No default route (air-gapped): fall back to the first usable address of `hostname -I`.
	got = detect(t, map[string]string{
		"ip":       `echo "RTNETLINK answers: Network is unreachable" >&2; exit 2`,
		"hostname": `echo "127.0.0.1 169.254.9.9 203.0.113.9 fd00::1"`,
	})
	if got != "203.0.113.9" {
		t.Errorf("hostname -I fallback: got %q", got)
	}
	// Nothing usable: empty, so install.sh stops and asks for --ip instead of guessing.
	got = detect(t, map[string]string{
		"ip":       `exit 2`,
		"hostname": `echo "127.0.0.1"`,
	})
	if got != "" {
		t.Errorf("no usable address: got %q, want empty", got)
	}
}

// ── the files install.sh copies, and the config it edits ───────────────────

var kitFilesRe = regexp.MustCompile(`(?s)KIT_FILES=\((.*?)\n\)`)

func kitFiles(t *testing.T) []string {
	t.Helper()
	m := kitFilesRe.FindSubmatch(readBytes(t, "install.sh"))
	if m == nil {
		t.Fatal("KIT_FILES not found in install.sh")
	}
	return strings.Fields(string(m[1]))
}

// install.sh copies a fixed list next to bin/ because check.sh finds its helpers by their
// location. Derive what the copied scripts actually call and make sure the list has it: a
// missing helper otherwise surfaces as one red step on a box, after a 90 s seed.
func TestInstall_KitHasEverythingTheScriptsCall(t *testing.T) {
	files := kitFiles(t)
	have := map[string]bool{}
	for _, f := range files {
		have[f] = true
		if _, err := os.Stat(filepath.Join("..", "..", f)); err != nil {
			t.Errorf("KIT_FILES names %s which does not exist: %v", f, err)
		}
	}
	// $SCRIPT_DIR/x and $REPO_ROOT/scripts/demo/x on non-comment lines. up.sh and down.sh are
	// only used when check.sh brings up its own demo (no --url), which install.sh never does.
	ref := regexp.MustCompile(`\$(?:\{?SCRIPT_DIR\}?|\{?REPO_ROOT\}?/scripts/demo)/([A-Za-z0-9_.-]+\.(?:sh|txt))`)
	notUsed := map[string]bool{"up.sh": true, "down.sh": true}
	for _, f := range files {
		if !strings.HasSuffix(f, ".sh") {
			continue
		}
		for line := range strings.SplitSeq(string(readBytes(t, filepath.Join("..", "..", f))), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range ref.FindAllStringSubmatch(line, -1) {
				if !have["scripts/demo/"+m[1]] && !notUsed[m[1]] {
					t.Errorf("%s calls scripts/demo/%s, which KIT_FILES does not copy", f, m[1])
				}
			}
		}
	}
	// check.sh --used reads the golden path document.
	if !have["docs/demo/GOLDEN-PATH.md"] {
		t.Error("KIT_FILES must include docs/demo/GOLDEN-PATH.md (golden-path-breakglass.sh reads it)")
	}
}

// install.sh edits the file `keyorix-server admin init --dev` writes by exact text. Each anchor
// must be in install.sh (so this test cannot drift from it) and in the live dev template (so a
// template edit fails here, not on somebody's box).
func TestInstall_ConfigAnchorsAreInTheDevTemplate(t *testing.T) {
	script := string(readBytes(t, "install.sh"))
	tmpl, err := configs.DevConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}
	// Written as python source literals (backslash-n) exactly as in install.sh.
	for _, anchor := range []string{
		`    # host: "127.0.0.1"\n    port: "8080"\n`,
		`      enabled: false  # DEV-ONLY: cleartext\n      cert_file: "certs/server.crt"     # Path to TLS certificate\n      key_file: "certs/server.key"      # Path to TLS key\n`,
		`    # DEV-ONLY: no metrics_token_file -- /metrics is unauthenticated\n`,
	} {
		if !strings.Contains(script, "'"+anchor+"'") {
			t.Errorf("install.sh no longer edits the anchor %q", anchor)
		}
		if !bytes.Contains(tmpl, []byte(strings.ReplaceAll(anchor, `\n`, "\n"))) {
			t.Errorf("the dev config template no longer contains %q: update install.sh", anchor)
		}
	}
}

// The parts of main() that need root and systemd and so cannot run here: these only show that
// the script text still has them (TestInstall_ServerUnitRunsUnprivileged checks the units).
func TestInstall_SecretsShape(t *testing.T) {
	script := string(readBytes(t, "install.sh"))
	for _, want := range []string{
		"server_unit > \"$UNIT_FILE\"",
		"renew_unit > \"/etc/systemd/system/$UNIT-renew.service\"",
		"--key-group \"$SVC_USER\"",
		"chown -hR \"$SVC_USER:$SVC_USER\" \"$STATE\"",
		"check_install_dir \"$DIR\"",
		"enable --now",
		"OnCalendar=daily",
		"umask 077",
		"--cacert",
		"KEYORIX_CA_FILE",
		"SSL_CERT_FILE",
		"--used",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.sh lacks %q", want)
		}
	}
	// The master password and the bootstrap token must never reach stdout or a command line:
	// they are only written to the 0600 files, via printf with the values taken from openssl.
	for n, line := range strings.Split(script, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if (strings.Contains(l, "echo") || strings.Contains(l, "info ") || strings.Contains(l, "say ")) &&
			(strings.Contains(l, "KEYORIX_MASTER_PASSWORD") || strings.Contains(l, "KEYORIX_BOOTSTRAP_TOKEN")) {
			t.Errorf("install.sh:%d prints a secret variable: %s", n+1, l)
		}
	}
	if strings.Contains(script, "rm -rf") || regexp.MustCompile(`\brm\s+-[a-z]*f`).MatchString(script) {
		t.Error("install.sh must never delete anything (it moves what it replaces to backup-<time>/)")
	}
}

// pki.sh deletes only the private work directory it created.
func TestPKI_OnlyRemovesItsOwnWorkDir(t *testing.T) {
	script := string(readBytes(t, "pki.sh"))
	if n := strings.Count(script, "rm -rf"); n != 1 || !strings.Contains(script, `rm -rf "$work"`) {
		t.Errorf("pki.sh must contain exactly one rm -rf, of its own work dir; found %d", n)
	}
	// And the work dir really is gone and nothing else is left behind after a run.
	needOpenssl(t)
	d := newPKIDirs(t)
	initPKI(t, d, nil)
	for _, dir := range []string{d.ca, d.leaf} {
		left, _ := filepath.Glob(filepath.Join(dir, ".work.*"))
		if len(left) != 0 {
			t.Errorf("work directory left behind: %v", left)
		}
	}
}

// ── the certificate never outlives the CA ──────────────────────────────────

// In the CA's last 820 days a full-length certificate would end after the CA; it would verify
// for nobody after the CA's end and every renewal would then fail. pki.sh caps it.
func TestPKI_LeafNeverOutlivesTheCA(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	out, code := d.pki(t, []string{"KEYORIX_LAN_CA_DAYS=100"}, "init", boxNames...)
	if code != 0 {
		t.Fatalf("init (exit %d): %s", code, out)
	}
	if !strings.Contains(out, "capped to") {
		t.Errorf("init did not say it capped the certificate: %s", out)
	}
	ca, leaf := readCert(t, filepath.Join(d.ca, "ca.crt")), readCert(t, filepath.Join(d.leaf, "server.crt"))
	// At least an hour before: the leaf is signed a moment after the CA's end is measured, and a
	// same-second race once let it end one second after the CA.
	if ca.NotAfter.Sub(leaf.NotAfter) < time.Hour {
		t.Errorf("certificate ends %v, less than an hour before the CA (%v)", leaf.NotAfter, ca.NotAfter)
	}
	if gap := ca.NotAfter.Sub(leaf.NotAfter).Hours(); gap > 48 {
		t.Errorf("certificate ends %.0f h before the CA: capped too far", gap)
	}
	// 100 days is well over the renewal threshold: nothing to do, no warning yet (90 days).
	out, code = d.pki(t, nil, "renew")
	if code != 0 || !strings.Contains(out, "certificate ok") || strings.Contains(out, "WARNING") {
		t.Errorf("renew of a capped certificate (exit %d): %s", code, out)
	}
}

// A CA in its last renewal window: the certificate it can sign ends with it. That must not be
// re-issued on every start (a pile of old/ copies, a restart from every timer run), and the
// operator must be told what to do before the CA ends.
func TestPKI_CANearItsEndWarnsAndDoesNotReissueInALoop(t *testing.T) {
	needOpenssl(t)
	d := newPKIDirs(t)
	out, code := d.pki(t, []string{"KEYORIX_LAN_CA_DAYS=20"}, "init", boxNames...)
	if code != 0 {
		t.Fatalf("init (exit %d): %s", code, out)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "--new-ca") {
		t.Errorf("init with a CA that ends in 20 days must warn and name --new-ca: %s", out)
	}
	before := readBytes(t, filepath.Join(d.leaf, "server.crt"))
	if out, code := d.pki(t, nil, "check"); code != 0 || !strings.Contains(out, "WARNING") {
		t.Errorf("check (exit %d) must pass and warn: %s", code, out)
	}
	for i := range 2 {
		out, code := d.pki(t, nil, "renew")
		if code != 0 || !strings.Contains(out, "certificate ok") || !strings.Contains(out, "--new-ca") {
			t.Errorf("renew %d (exit %d): %s", i+1, code, out)
		}
	}
	if !bytes.Equal(before, readBytes(t, filepath.Join(d.leaf, "server.crt"))) {
		t.Error("renew re-issued a certificate that a new one could not outlast")
	}
	if olds, _ := filepath.Glob(filepath.Join(d.leaf, "old", "*")); len(olds) != 0 {
		t.Errorf("renew piled up old certificates: %v", olds)
	}
	// A certificate that could last longer under the same CA is still renewed.
	d2 := newPKIDirs(t)
	initPKI(t, d2, []string{"KEYORIX_LAN_CA_DAYS=40", "KEYORIX_LAN_LEAF_DAYS=5"})
	if out, code := d2.pki(t, nil, "renew"); code != 0 || !strings.Contains(out, "renewed") {
		t.Errorf("a 5-day certificate under a 40-day CA must be renewed (exit %d): %s", code, out)
	}
	if dd := days(readCert(t, filepath.Join(d2.leaf, "server.crt"))); dd < 38 || dd > 40 {
		t.Errorf("renewed certificate %.1f days, want the CA's remaining 39-40", dd)
	}
}

// ── the key is readable by the server's group, the CA key by root only ────

func TestPKI_KeyGroup(t *testing.T) {
	needOpenssl(t)
	grp, code := run(t, nil, "id", "-gn")
	if code != 0 {
		t.Skip("id -gn failed")
	}
	grp = strings.TrimSpace(grp)
	d := newPKIDirs(t)
	// First without --key-group (an older install), then a renew with it fixes the modes.
	initPKI(t, d, nil)
	if m := perm(t, filepath.Join(d.leaf, "server.key")); m != 0o600 {
		t.Errorf("server.key without --key-group: mode %o, want 600", m)
	}
	if out, code := d.pki(t, nil, "renew", "--key-group", grp); code != 0 {
		t.Fatalf("renew --key-group (exit %d): %s", code, out)
	}
	check := func(when string, d pkiDirs) {
		t.Helper()
		for path, want := range map[string]os.FileMode{
			filepath.Join(d.leaf, "server.key"): 0o640, d.leaf: 0o750,
			filepath.Join(d.ca, "ca.key"): 0o600, d.ca: 0o700,
		} {
			if m := perm(t, path); m != want {
				t.Errorf("%s: %s mode %o, want %o", when, path, m, want)
			}
		}
		for _, path := range []string{filepath.Join(d.leaf, "server.key"), d.leaf} {
			if gid := fileGID(t, path); gid != os.Getgid() {
				t.Errorf("%s: %s group %d, want %d (%s)", when, path, gid, os.Getgid(), grp)
			}
		}
	}
	check("after renew --key-group", d)
	// Issued and re-issued keys get the same modes from their first moment in place.
	d = newPKIDirs(t)
	initPKI(t, d, []string{"KEYORIX_LAN_LEAF_DAYS=20"}, "--key-group", grp)
	check("after init --key-group", d)
	if out, code := d.pki(t, nil, "renew", "--key-group", grp); code != 0 || !strings.Contains(out, "renewed") {
		t.Fatalf("renew --key-group of a due certificate (exit %d): %s", code, out)
	}
	check("after a re-issue", d)
	// Replaced keys stay root-only.
	if olds, _ := filepath.Glob(filepath.Join(d.leaf, "old", "*", "server.key")); len(olds) == 0 {
		t.Error("no replaced key under old/")
	} else if m := perm(t, filepath.Dir(olds[0])); m != 0o700 {
		t.Errorf("old/ directory mode %o, want 700", m)
	}
	if out, code := d.pki(t, nil, "renew", "--key-group", "bad group"); code == 0 || !strings.Contains(out, "not a group name") {
		t.Errorf("a bad --key-group was accepted (exit %d): %s", code, out)
	}
}

// ── install.sh never takes over a directory that is not its own ────────────

func TestInstall_RefusesAnUnsafeExistingDir(t *testing.T) {
	needOpenssl(t)
	root := t.TempDir()
	mk := func(name string, mode os.FileMode, files ...string) string {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(p, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	shared := mk("shared", 0o777|os.ModeSticky) // what /tmp looks like
	groupWritable := mk("group-writable", 0o775)
	populated := mk("populated", 0o755, "somebody-else's-file")
	private := mk("private", 0o700)
	empty := mk("empty", 0o755)
	earlier := mk("earlier-install", 0o755, ".keyorix-demo-lan", "keyorix-demo-ca.crt")
	link := filepath.Join(root, "link")
	if err := os.Symlink(empty, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dir, want string // want "" = accepted
	}{
		{shared, "writable by group or others"},
		{groupWritable, "writable by group or others"},
		{populated, "is not empty"},
		{private, "others may not traverse it"},
		{link, "symbolic link"},
		{empty, ""},
		{earlier, ""},
		{filepath.Join(root, "new"), ""},
	} {
		t.Run(filepath.Base(tc.dir), func(t *testing.T) {
			before, _ := os.Lstat(tc.dir)
			out, code := run(t, nil, "bash", "-c", `source ./install.sh; check_install_dir "$1"; echo accepted`, "x", tc.dir)
			switch {
			case tc.want == "" && (code != 0 || !strings.Contains(out, "accepted")):
				t.Errorf("refused (exit %d): %s", code, out)
			case tc.want != "" && (code == 0 || !strings.Contains(out, tc.want)):
				t.Errorf("exit %d, want a refusal containing %q: %s", code, tc.want, out)
			}
			if before != nil {
				if after, _ := os.Lstat(tc.dir); after.Mode() != before.Mode() {
					t.Errorf("mode changed from %v to %v", before.Mode(), after.Mode())
				}
			}
		})
	}

	// The whole installer stops on it before anything else, and leaves /tmp-like modes alone.
	bins := t.TempDir()
	fakeELF(t, bins, "keyorix", "keyorix-server", "totpgen")
	out, code := run(t, nil, "bash", "install.sh", "--bin-dir", bins, "--dir", shared)
	if code == 0 || !strings.Contains(out, "writable by group or others") {
		t.Errorf("install.sh --dir <shared dir> (exit %d): %s", code, out)
	}
	if fi, _ := os.Stat(shared); fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Errorf("install.sh changed the shared directory's mode to %v", fi.Mode())
	}
	if entries, _ := os.ReadDir(shared); len(entries) != 0 {
		t.Errorf("install.sh wrote into the refused directory: %v", entries)
	}
}

// ── the systemd units, as install.sh writes them ───────────────────────────

// renderUnit runs one of install.sh's unit functions with the variables main() sets.
func renderUnit(t *testing.T, fn, port string) (map[string][]string, []string) {
	t.Helper()
	script := `source ./install.sh
DIR=/opt/keyorix-demo; STATE=$DIR/state; PKI=$DIR/pki; ENVF=$DIR/env; CA_DIR=$PKI/ca; LEAF_DIR=$PKI/leaf
UNIT=keyorix-lan-keyorix-demo; SVC_USER=keyorix-lan; PORT=` + port + `; MARKER="# keyorix demo-lan install.sh dir=$DIR"
` + fn
	out, code := run(t, nil, "bash", "-c", script)
	if code != 0 {
		t.Fatalf("%s (exit %d): %s", fn, code, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	kv := map[string][]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			kv[k] = append(kv[k], v)
		}
	}
	return kv, lines
}

func one(t *testing.T, kv map[string][]string, key string) string {
	t.Helper()
	if len(kv[key]) != 1 {
		t.Errorf("%s= appears %d times, want once", key, len(kv[key]))
		return ""
	}
	return kv[key][0]
}

// The server must not run as root: a 0.0.0.0 listener as root could read the CA key. These
// assert the generated unit itself (rendered by install.sh's own function), not words in the
// script. What they cannot show: that systemd on a real box accepts and applies every directive
// (docs/demo/LAN-TLS.md's manual run covers that).
func TestInstall_ServerUnitRunsUnprivileged(t *testing.T) {
	kv, lines := renderUnit(t, "server_unit", "8080")
	if lines[0] != "# keyorix demo-lan install.sh dir=/opt/keyorix-demo" {
		t.Errorf("first line %q is not the installer's marker", lines[0])
	}
	if u := one(t, kv, "User"); u == "" || u == "root" || u == "0" {
		t.Errorf("User=%q: the server must run as a dedicated user", u)
	}
	if g := one(t, kv, "Group"); g != one(t, kv, "User") {
		t.Errorf("Group=%q, want the service user's own group (it reads the key through it)", g)
	}
	pre := one(t, kv, "ExecStartPre")
	if !strings.HasPrefix(pre, "+/opt/keyorix-demo/pki/pki.sh renew ") || !strings.Contains(pre, "--key-group keyorix-lan") {
		t.Errorf("ExecStartPre=%q: the renewal must run as root (+) and hand the key to the server's group", pre)
	}
	if start := one(t, kv, "ExecStart"); strings.ContainsAny(start[:1], "+!@-:") || start != "/opt/keyorix-demo/bin/keyorix-server" {
		t.Errorf("ExecStart=%q runs with a privilege prefix or something other than the server", start)
	}
	for key, want := range map[string]string{
		"CapabilityBoundingSet": "", "AmbientCapabilities": "", "NoNewPrivileges": "yes",
		"ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes",
		"ReadWritePaths": "/opt/keyorix-demo/state", "RestrictSUIDSGID": "yes", "UMask": "0077",
		"Restart": "always", "EnvironmentFile": "/opt/keyorix-demo/env", "WorkingDirectory": "/opt/keyorix-demo/state",
	} {
		if got := one(t, kv, key); got != want {
			t.Errorf("%s=%q, want %q", key, got, want)
		}
	}
	hidden := strings.Fields(one(t, kv, "InaccessiblePaths"))
	sort.Strings(hidden)
	if strings.Join(hidden, " ") != "/opt/keyorix-demo/env /opt/keyorix-demo/pki/ca" {
		t.Errorf("InaccessiblePaths=%v, want the CA directory and the EnvironmentFile", hidden)
	}
	// A port below 1024 needs exactly one capability, and nothing more.
	kv, _ = renderUnit(t, "server_unit", "443")
	for _, key := range []string{"CapabilityBoundingSet", "AmbientCapabilities"} {
		if got := one(t, kv, key); got != "CAP_NET_BIND_SERVICE" {
			t.Errorf("port 443: %s=%q, want CAP_NET_BIND_SERVICE only", key, got)
		}
	}
	// The timer's renewal also keeps the key readable by the server and restarts it.
	kv, _ = renderUnit(t, "renew_unit", "8080")
	if s := one(t, kv, "ExecStart"); !strings.Contains(s, "--key-group keyorix-lan") || !strings.Contains(s, "--restart-unit keyorix-lan-keyorix-demo.service") {
		t.Errorf("renew unit ExecStart=%q", s)
	}
	if _, ok := kv["User"]; ok {
		t.Error("the renewal unit must run as root (it signs with the CA key)")
	}
}

func fileGID(t *testing.T, path string) int {
	t.Helper()
	out, code := run(t, nil, "bash", "-c", `ls -nd "$1" | awk '{print $4}'`, "x", path)
	if code != 0 {
		t.Fatalf("ls -nd %s: %s", path, out)
	}
	gid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("group of %s: %q", path, out)
	}
	return gid
}
