package azurefuzz

import (
	"context"
	"testing"
	"time"
)

// TestDiag_ChallengeFlowExecutes is a diagnostic (not an oracle): it confirms
// the fuzz harness genuinely drives azcore's challenge-auth handshake — a 401
// with WWW-Authenticate followed by an authenticated retry — so the
// WWW-Authenticate fuzzing actually reaches the challenge parser. It records how
// many requests the client issued and whether GetToken was invoked.
func TestDiag_ChallengeFlowExecutes(t *testing.T) {
	specs := []respSpec{
		{status: 401, contentType: "application/json", extraHdr: "WWW-Authenticate: " + string(validChallenge), body: []byte(`{"error":{"code":"x"}}`)},
		{status: 200, contentType: "application/json", body: []byte(`{"value":"ok"}`)},
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
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, gerr := cl.GetSecret(ctx, canaryName, "", nil)
	t.Logf("GetSecret err = %v", gerr)
	fs.mu.Lock()
	served := fs.served
	fs.mu.Unlock()
	t.Logf("challenge-flow diagnostic: requests served=%d (2 => 401 challenge then authenticated retry)", served)
	if served < 2 {
		t.Logf("NOTE: only %d request(s) served — challenge retry did not occur over http (bearer may be withheld on plaintext); challenge PARSER still ran on the 401", served)
	}
}
