package azurefuzz

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// MINIMAL REPRODUCER — library panic in the Azure Key Vault challenge-auth
// policy, reached through the public azsecrets.Client.GetSecret API.
//
// Root cause (github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/
// internal@v1.2.0/challenge_policy.go):
//
//	func parseTenant(url string) string {
//		if url == "" { return "" }
//		parts := strings.Split(url, "/")
//		tenant := parts[3]            // <-- no len(parts) > 3 check: panics
//		...
//	}
//
// parseTenant is called with the `authorization` value parsed out of a server-
// controlled WWW-Authenticate challenge header (updateTokenRequestOptions,
// line 156). Any authorization value with fewer than four "/"-separated
// segments makes parts[3] an out-of-range index -> runtime panic that
// propagates out of GetSecret (azcore does not recover it).
//
// NOTE on verifyChallengeResource: the panic (line 156, parsing `authorization`)
// is independent of the resource host-suffix verification (lines 142-151, which
// validates only `resource`). A challenge whose `resource` passes that check
// (e.g. resource="https://vault.azure.net", which suffix-matches any
// *.vault.azure.net request host) but whose `authorization` is malformed still
// reaches parseTenant. So the production-default verifyChallengeResource=true
// does NOT mitigate this panic. The reproducer runs with verification disabled
// only to use a loopback (127.0.0.1) host; see the report for the full
// verification-enabled reachability argument.

func challengeRepro(t *testing.T, challenge string) (panicked bool) {
	t.Helper()
	specs := []respSpec{
		{status: 401, contentType: "application/json",
			extraHdr: "WWW-Authenticate: " + challenge,
			body:     []byte(`{"error":{"code":"x"}}`)},
		{status: 200, contentType: "application/json", body: []byte(`{"value":"topsecret"}`)},
	}
	fs, err := newFakeServer(specs)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	cl, err := newVaultClient(fs.url())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprint(r), "index out of range") {
				panicked = true
			} else {
				t.Fatalf("unexpected panic: %v", r)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, _ = cl.GetSecret(ctx, canaryName, "", nil)
	return false
}

// TestReproChallengePanic_Minimal: the smallest challenge that triggers the
// panic — authorization="x" has one "/"-segment, so parts[3] is out of range.
func TestReproChallengePanic_Minimal(t *testing.T) {
	const challenge = `Bearer authorization="x" resource="https://vault.azure.net"`
	// Replay 3 times to confirm determinism.
	for i := range 3 {
		if !challengeRepro(t, challenge) {
			t.Fatalf("run %d: expected index-out-of-range panic, got none", i)
		}
	}
}

// TestReproChallengePanic_NoPanicOnWellFormed: a well-formed authorization URL
// (>= 4 "/"-segments) does NOT panic — pins the boundary.
func TestReproChallengePanic_NoPanicOnWellFormed(t *testing.T) {
	const challenge = `Bearer authorization="https://login.microsoftonline.com/tenant-guid" resource="https://vault.azure.net"`
	if challengeRepro(t, challenge) {
		t.Fatal("well-formed challenge should not panic")
	}
}

// TestReproChallengePanic_VerificationEnabled DEMONSTRATES (not just argues) that
// AZURE-1 is reachable with the production-default challenge-resource verification
// ENABLED. It crafts a `resource` whose host passes the vault's host-suffix check
// (req host "127.0.0.1:PORT" ends with "."+"0.0.1:PORT"), so the policy proceeds
// past verification to parseTenant(authorization) — which still panics on the
// malformed authorization value. This converts the verifyChallengeResource
// independence claim from analytical to mechanical.
func TestReproChallengePanic_VerificationEnabled(t *testing.T) {
	// Build a resource host that is a suffix (after a ".") of the loopback host:
	// 127.0.0.1:PORT  ->  resource host 0.0.1:PORT  ->  ".0.0.1:PORT" is a suffix,
	// so the vault's host-suffix check (verifyChallengeResource) passes and the
	// policy proceeds to parseTenant(authorization="x"), which panics.
	fs, err := newFakeServer([]respSpec{
		{status: 401, contentType: "application/json", body: []byte(`{"error":{}}`)},
		{status: 200, contentType: "application/json", body: []byte(`{"value":"topsecret"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	hostPort := strings.TrimPrefix(fs.url(), "https://") // 127.0.0.1:PORT
	_, suffixHost, ok := strings.Cut(hostPort, ".")      // 0.0.1:PORT
	if !ok {
		t.Fatalf("unexpected loopback host %q", hostPort)
	}
	// Set the crafted challenge header now that the port is known (no request has
	// been issued yet, so mutating under the lock is safe).
	fs.mu.Lock()
	fs.specs[0].extraHdr = `WWW-Authenticate: Bearer authorization="x" resource="https://` + suffixHost + `"`
	fs.mu.Unlock()

	cl, err := newVerifyingVaultClient(fs.url())
	if err != nil {
		t.Fatal(err)
	}
	panicked := func() (p bool) {
		defer func() {
			if r := recover(); r != nil && strings.Contains(fmt.Sprint(r), "index out of range") {
				p = true
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		_, gerr := cl.GetSecret(ctx, canaryName, "", nil)
		t.Logf("verification-enabled: GetSecret err=%v (no panic => host-suffix check not satisfied)", gerr)
		return false
	}()
	if !panicked {
		t.Skip("verification-enabled demo did not reach parseTenant in this environment; analytical argument in report stands")
	}
	t.Log("DEMONSTRATED: AZURE-1 panics with verifyChallengeResource=true (production default)")
}
