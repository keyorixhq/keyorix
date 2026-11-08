// mfa_reset_sweep_reuse_test.go -- the soundness gate for the world reuse in
// TestMFAResetOpsFaultSweep, which keeps each world's encryption service across
// resets on top of the usual table wipe (keepEncryptionAcrossResets).
//
// TestWorldReuseSoundness replays the fuzz corpus, which has no MFA reset input, and
// does not keep the service. This gate replays a sample of the sweep's own inputs with
// fresh worlds and with the reused pair, forward and reversed, and requires the same
// verdict and the same state outside the outcome-log tables. Its red half plants a
// leak in each table the MFA reset fixture and ops write.
package faultops

import (
	"os"
	"slices"
	"testing"
)

// mfaResetReuseEquivEnv set to "all" makes the gate cover every sweep input instead of
// a sample (a manual run: about twenty times the cost).
const mfaResetReuseEquivEnv = "KEYORIX_MFA_SWEEP_REUSE_EQUIV"

// mfaResetReusePerOp is how many inputs per op an ordinary run compares.
const mfaResetReusePerOp = 4

// mfaResetReuseSample picks inputs per op spread over the methods. The added i walks
// across the three fault kinds, which are adjacent in the input list.
func mfaResetReuseSample(t *testing.T) [][]byte {
	t.Helper()
	w := buildReusableFaultWorld(t, nil)
	var out [][]byte
	for _, key := range mfaResetOps {
		inputs := mfaResetSweepInputs(t, w, key)
		if os.Getenv(mfaResetReuseEquivEnv) == "all" {
			out = append(out, inputs...)
			continue
		}
		stride := len(inputs) / mfaResetReusePerOp
		for i := range mfaResetReusePerOp {
			out = append(out, inputs[i*stride+i])
		}
	}
	return out
}

func mfaResetFreshBaseline(t *testing.T, inputs [][]byte) []verdict {
	t.Helper()
	baseline := make([]verdict, len(inputs))
	for i, in := range inputs {
		baseline[i] = captureVerdict(t, "fresh", in, nil, nil)
	}
	return baseline
}

// TestMFAResetSweepReuseMatchesFreshWorlds is the gate. See the file comment.
func TestMFAResetSweepReuseMatchesFreshWorlds(t *testing.T) {
	if testing.Short() {
		t.Skip("builds fresh worlds per input; run without -short")
	}
	inputs := mfaResetReuseSample(t)
	baseline := mfaResetFreshBaseline(t, inputs)
	fired := 0
	for _, v := range baseline {
		if v.fired {
			fired++
		}
	}
	if fired != len(inputs) {
		t.Fatalf("%d of %d sampled inputs fired a fault with fresh worlds, every sweep input must", fired, len(inputs))
	}
	t.Run("forward", func(t *testing.T) {
		ref, w := buildMFAResetSweepWorlds(t)
		for i, in := range inputs {
			assertVerdictsMatch(t, i, "forward", captureVerdict(t, "reused", in, ref, w), baseline[i])
		}
	})
	t.Run("reversed", func(t *testing.T) {
		ref, w := buildMFAResetSweepWorlds(t)
		for i, in := range slices.Backward(inputs) {
			assertVerdictsMatch(t, i, "reversed", captureVerdict(t, "reused", in, ref, w), baseline[i])
		}
	})
	t.Logf("reuse gate: %d MFA reset inputs identical with fresh and reused worlds, forward and reversed", len(inputs))
}

// TestMFAResetSweepReuseCatchesPlantedStateLeak is the gate's red proof: a reset that
// leaks any one MFA reset table must make the comparison differ.
func TestMFAResetSweepReuseCatchesPlantedStateLeak(t *testing.T) {
	if os.Getenv("KEYORIX_RUN_REDPROOF_TESTS") == "" {
		t.Skip("manual red-proof, skipped by default: set KEYORIX_RUN_REDPROOF_TESTS=1. It plants state leaks, so " +
			"its nested subtests fail by design; look for \"planted state leak correctly detected\".")
	}
	inputs := mfaResetReuseSample(t)
	baseline := mfaResetFreshBaseline(t, inputs)
	probe := buildReusableFaultWorld(t, nil)
	for _, leaked := range []string{
		"mfa_reset_requests", "mfa_secrets", "mfa_recovery_codes", "web_authn_credentials",
		"sessions", "personal_access_tokens", "notifications",
	} {
		if !probe.db.Migrator().HasTable(leaked) {
			t.Fatalf("plant target table %q does not exist: the plant would be a silent no-op", leaked)
		}
		mismatches := 0
		t.Run("leak "+leaked, func(t *testing.T) {
			leakTableForTest = leaked
			defer func() { leakTableForTest = "" }()
			ref, w := buildMFAResetSweepWorlds(t)
			// Twice over, so rows leaked by the last input of the first pass reach
			// the first inputs of the second.
			for range 2 {
				for i, in := range inputs {
					if !verdictsMatch(captureVerdict(t, "leaky", in, ref, w), baseline[i]) {
						mismatches++
					}
				}
			}
		})
		if mismatches == 0 {
			t.Fatalf("planted leak of %s produced no mismatch: the gate does not see that table leak", leaked)
		}
		t.Logf("planted state leak correctly detected: %s: %d mismatches", leaked, mismatches)
	}
}
