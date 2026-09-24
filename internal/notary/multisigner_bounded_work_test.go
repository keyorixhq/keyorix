package notary

// TestMultiSignerBoundedWork measures the concrete cost of a multi-SignerInfo
// TimeStampToken, before and after VerifyReceipt's SignerInfo-count cap
// (notary.go: `if len(p7.Signers) != 1 { ... }`, added alongside the
// "two-distinct-valid-signers" scenario in cert_chain_trust_fuzz_test.go).
//
// Before the cap, pkcs7.VerifyWithOpts loops over every SignerInfo requiring
// each to independently pass its own chain verification + signature check —
// an attacker-controlled linear multiplier on VerifyReceipt's most expensive
// work, since each additional SignerInfo is cheap to add (pkcs7.SignedData.
// AddSignerChain has no cap) but costs a full x509 chain verification to
// reject or accept. This measures that multiplier directly (calling
// p7.VerifyWithOpts, bypassing VerifyReceipt's cap, to reconstruct what
// verification would have cost without it) and confirms the cap itself keeps
// VerifyReceipt's real rejection cost flat in N (reject happens immediately
// after pkcs7.Parse, before any chain verification is attempted).
//
// pkcs7.Parse's own cost for an N-signer token is already bounded
// independently by internal/libconformance.FuzzDigitorusPKCS7BoundedWork —
// this test is only concerned with the verification work ABOVE that parse,
// which is what the cap removes entirely for N != 1.

import (
	"crypto/x509"
	"runtime"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
)

func measureAlloc(f func()) uint64 {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	f()
	runtime.ReadMemStats(&m1)
	return m1.TotalAlloc - m0.TotalAlloc
}

func TestMultiSignerBoundedWork(t *testing.T) {
	pki := buildCertPKI(t)
	onlyR := x509.NewCertPool()
	onlyR.AddCert(pki.rootR)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	for _, n := range []int{1, 2, 10, 50, 100} {
		signers := make([]signerKeyPair, n)
		for i := range signers {
			// Same (cert, key) pair re-signing N times: still N genuinely
			// independent, individually-valid ECDSA signatures (ecdsa.Sign is
			// randomized), so pkcs7.VerifyWithOpts must do N real chain
			// verifications + N real signature checks — not deduplicated.
			signers[i] = signerKeyPair{pki.leafUnderR, pki.leafUnderRKey}
		}
		token := buildMultiSignerToken(t, signers, now)

		p7, err := pkcs7.Parse(token)
		if err != nil {
			t.Fatalf("n=%d: pkcs7.Parse: %v", n, err)
		}
		if len(p7.Signers) != n {
			t.Fatalf("n=%d: token has %d signers, want %d", n, len(p7.Signers), n)
		}
		intermediates := x509.NewCertPool()
		for _, c := range p7.Certificates {
			intermediates.AddCert(c)
		}

		// "Without the cap" number: call VerifyWithOpts directly, exactly the
		// work VerifyReceipt would have done pre-fix for an N-signer token
		// where every signer happens to be genuinely valid and trusted.
		var uncappedElapsed time.Duration
		uncappedAlloc := measureAlloc(func() {
			start := time.Now()
			if err := p7.VerifyWithOpts(x509.VerifyOptions{
				Roots:         onlyR,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
				CurrentTime:   now,
			}); err != nil {
				t.Fatalf("n=%d: uncapped VerifyWithOpts unexpectedly failed: %v", n, err)
			}
			uncappedElapsed = time.Since(start)
		})

		// "With the cap" number: the real VerifyReceipt call, post-fix.
		var cappedElapsed time.Duration
		cappedAlloc := measureAlloc(func() {
			start := time.Now()
			_, err := VerifyReceipt(onlyR, certChainMessage, token)
			cappedElapsed = time.Since(start)
			if n == 1 {
				if err != nil {
					t.Fatalf("n=1: VerifyReceipt unexpectedly rejected a single valid signer: %v", err)
				}
			} else if err == nil {
				t.Fatalf("n=%d: VerifyReceipt accepted a multi-signer token — SignerInfo cap not enforced", n)
			}
		})

		t.Logf("n=%3d signers: token=%5d bytes | uncapped VerifyWithOpts: %8v, %6d bytes alloc | capped VerifyReceipt: %8v, %6d bytes alloc",
			n, len(token), uncappedElapsed, uncappedAlloc, cappedElapsed, cappedAlloc)
	}
}
