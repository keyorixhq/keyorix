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
	for i := 0; i < 3; i++ {
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
