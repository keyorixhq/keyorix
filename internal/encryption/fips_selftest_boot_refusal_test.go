package encryption

import (
	"errors"
	"strings"
	"testing"
)

// FIPS-TAILS-2 item 6: the boot refusal itself, driven in default mode (no CI
// job runs GODEBUG=fips140=only, so TestBootFIPSSelfTest_FailingPathRefusesBoot
// only reaches its no-op branch there). With enforcement forced on and one
// path stubbed to fail, BootFIPSSelfTest returns the *FIPSSelfTestError naming
// it, the later path does not run, and the text server/main.go prints is the
// one docs/operator/startup-refusals.md documents.
func TestBootFIPSSelfTest_EnforcedStubbedFailureNamesThePath(t *testing.T) {
	savedPaths, savedEnforced := fipsSelfTestPaths, fipsSelfTestEnforced
	t.Cleanup(func() {
		fipsSelfTestPaths, fipsSelfTestEnforced = savedPaths, savedEnforced
		fipsSelfTestMu.Lock()
		fipsSelfTestRan, fipsSelfTestResult = false, nil
		fipsSelfTestMu.Unlock()
	})
	fipsSelfTestEnforced = func() bool { return true }
	var laterRan bool
	fipsSelfTestPaths = []fipsSelfTestPath{
		{"DEK wrap/unwrap (stub)", func() error { return nil }},
		{"secret encrypt/decrypt (stub)", func() error {
			panic("crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode")
		}},
		{"later path", func() error { laterRan = true; return nil }},
	}

	err := BootFIPSSelfTest()
	var st *FIPSSelfTestError
	if !errors.As(err, &st) || st.Path != "secret encrypt/decrypt (stub)" {
		t.Fatalf("err = %v, want *FIPSSelfTestError naming the failing path", err)
	}
	if laterRan {
		t.Error("a path after the failing one ran")
	}
	refusal := "Refusing to start: " + err.Error() // server/main.go's log.Fatalf
	for _, want := range []string{"fips140 self-test failed on", "secret encrypt/decrypt (stub)", "not allowed in FIPS 140-only mode"} {
		if !strings.Contains(refusal, want) {
			t.Errorf("refusal %q does not contain %q", refusal, want)
		}
	}
	if line := FIPSSelfTestPostureLine(); !strings.Contains(line, "self-test FAILED") {
		t.Errorf("posture line = %q, want FAILED", line)
	}

	// Enforcement off: nothing runs and boot goes on.
	fipsSelfTestEnforced = func() bool { return false }
	ran := false
	fipsSelfTestPaths = []fipsSelfTestPath{{"x", func() error { ran = true; return errors.New("refused") }}}
	if err := BootFIPSSelfTest(); err != nil || ran {
		t.Fatalf("not enforced: err = %v, ran = %v; want nil, false", err, ran)
	}
}
