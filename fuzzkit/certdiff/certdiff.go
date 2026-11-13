// Package certdiff is diffkit Instance B: a differential oracle over X.509
// certificate-chain trust decisions. It compares Go's crypto/x509
// (Certificate.Verify) against the openssl(1) CLI ("openssl verify") on the same
// Frankencert-style generated chain, and reports any accept/reject disagreement
// that the documented-differences table does not explain.
//
// WHAT THE ORACLE VERIFIES: that crypto/x509 and openssl reach the SAME
// trust decision (accept vs reject) for a chain built from a configured root,
// optional intermediates and a leaf, with time pinned to a single instant and
// EKU/purpose checking disabled on BOTH sides (see below).
//
// WHAT IT DOES NOT VERIFY:
//   - Which chain was built, or any policy detail beyond the final yes/no.
//   - EKU / purpose nesting: both sides run with purpose checking OFF (Go
//     KeyUsages = [ExtKeyUsageAny], openssl with no -purpose) so that the many
//     well-known Go-vs-openssl purpose-model differences do not drown the
//     structural signal. EKU mutations therefore do not drive this oracle; a
//     dedicated EKU oracle would pin a matching purpose on both sides.
//   - CRL / OCSP revocation (neither side is given revocation data).
//   - That the SHARED decision is correct. A differential oracle is silent when
//     both libraries share a blind spot.
//   - Raw-DER parser divergence: both verifiers receive the SAME DER that Go's
//     x509.CreateCertificate produced and Go's parser already accepted, so this
//     instance targets trust-policy divergence, not parse divergence.
package certdiff

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/fuzzkit/diffkit"
)

// perImplTimeout bounds each verifier. openssl is a child process; Go's Verify
// is in-process. Both are fast on these tiny chains; the timeout only guards a
// pathological hang.
const perImplTimeout = 10 * time.Second

// --- Impl 1: Go crypto/x509 ---------------------------------------------------

type goX509 struct{}

func (goX509) Name() string { return "crypto/x509" }

func (goX509) Run(_ context.Context, ch *chain) (string, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ch.root)
	inter := x509.NewCertPool()
	for _, c := range ch.inters {
		inter.AddCert(c)
	}
	_, err := ch.leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   ch.now,
		// Disable the ServerAuth default so purpose checking does not confound the
		// structural trust decision (see package doc).
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return "", err
	}
	return ch.leafFP, nil
}

// --- Impl 2: openssl verify ---------------------------------------------------

type opensslVerify struct {
	bin string
}

func (opensslVerify) Name() string { return "openssl" }

func (o opensslVerify) Run(ctx context.Context, ch *chain) (string, error) {
	dir, err := os.MkdirTemp("", "certdiff-")
	if err != nil {
		return "", fmt.Errorf("mktemp: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	rootPEM := filepath.Join(dir, "root.pem")
	leafPEM := filepath.Join(dir, "leaf.pem")
	if err := writePEM(rootPEM, ch.root.Raw); err != nil {
		return "", err
	}
	if err := writePEM(leafPEM, ch.leaf.Raw); err != nil {
		return "", err
	}

	args := []string{"verify", "-CAfile", rootPEM, "-attime", strconv.FormatInt(ch.now.Unix(), 10)}
	if len(ch.inters) > 0 {
		chainPEM := filepath.Join(dir, "inter.pem")
		var buf bytes.Buffer
		for _, c := range ch.inters {
			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
				return "", err
			}
		}
		if err := os.WriteFile(chainPEM, buf.Bytes(), 0o600); err != nil {
			return "", err
		}
		args = append(args, "-untrusted", chainPEM)
	}
	args = append(args, leafPEM)

	// The command is the static name "openssl" (NewComparator already proved it
	// resolves via exec.LookPath); args are fixed flags plus temp-dir paths this
	// function wrote itself, never external input.
	cmd := exec.CommandContext(ctx, "openssl", args...) // #nosec G204 -- static command, fixed args
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		// Exit 0 == verification OK.
		return ch.leafFP, nil
	}
	// A non-zero exit is a reject; surface the reason as the error (reject class).
	if _, ok := errors.AsType[*exec.ExitError](runErr); ok {
		return "", fmt.Errorf("openssl reject: %s", bytes.TrimSpace(out))
	}
	// Anything else (binary missing, could not spawn) is an infrastructure error,
	// not a trust decision — bubble it up so the harness can treat it distinctly.
	return "", fmt.Errorf("openssl exec error: %w (%s)", runErr, bytes.TrimSpace(out))
}

func writePEM(path string, der []byte) error {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// --- Comparator ---------------------------------------------------------------

func decide(o diffkit.Outcome[string]) diffkit.Verdict {
	v := diffkit.DecideFrom(o)
	if o.Decision == diffkit.DecisionAccept {
		v.Subject = o.Value
	}
	return v
}

// documentedDiffs is the table of KNOWN, REASONED crypto/x509-vs-openssl
// differences. Each row must cite which side is right and why, per RFC 5280.
// An undocumented divergence fails. The table starts intentionally EMPTY: rows
// are added only after a divergence is triaged and understood (so the table can
// never silently pre-swallow a real finding). Candidate rows observed during
// this campaign are recorded in .scratch/kd-REPORT.md before being promoted here.
var documentedDiffs []diffkit.DocumentedDiff

// NewComparator builds the Comparator. bin is the openssl binary path (from
// exec.LookPath). It returns an error if openssl is unavailable so callers can
// skip cleanly rather than report a bogus divergence.
func NewComparator() (diffkit.Comparator[*chain, string], error) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		return diffkit.Comparator[*chain, string]{}, fmt.Errorf("openssl not on PATH: %w", err)
	}
	return diffkit.Comparator[*chain, string]{
		Impls:   []diffkit.Impl[*chain, string]{goX509{}, opensslVerify{bin: bin}},
		Timeout: perImplTimeout,
		Decide:  decide,
		Diffs:   documentedDiffs,
	}, nil
}
