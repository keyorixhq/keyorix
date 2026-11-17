//go:build linux

package cmd

// Committed red/green guard for the DRP1 net/connectivity replay fail-open (the
// drop-one sibling of DD3 that TRUNCATE/CORRUPT reaches but the recording-gap fix
// does not). The `net/connectivity` derived cache holds the recorded ping/DNS
// probe. When that blob is present but EMPTY/garbled on replay, the probe decodes
// to its zero value — 0 ms gateway/internet latency, DNS-ok — which reads as a
// HEALTHY Network, flipping a baseline CRIT to OK. No recording GAP is counted
// (the blob is present), so Result.NotRecorded stays false and the DD3 synthetic
// not_recorded INFO never fires. The fix makes probeConnectivity treat an
// unreadable cached probe on replay as "not measured" (ConnectivityProbeDisabled)
// rather than a fabricated healthy result.
//
// RED before the fix: Network CRIT -> OK on both fixtures. GREEN after: Network
// stays non-OK (degrades to INFO "not measured").

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestDRP1ConnectivityCacheCorruptNotFalseOK(t *testing.T) {
	dd2CapParallelism()
	for _, fx := range dd2CommittedFixtures(t) {
		fx := fx
		t.Run(baseName(fx), func(t *testing.T) {
			b0, err := loadBundle(fx)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			dir := t.TempDir()
			if err := b0.Save(dir); err != nil {
				t.Fatalf("save: %v", err)
			}
			tree, err := readTree(dir)
			if err != nil {
				t.Fatalf("readTree: %v", err)
			}

			// Baseline must have Network non-OK, else this guard is vacuous here.
			baseV, _, _ := drp1Replay(dir)
			if baseV["Network"] == "" || baseV["Network"] == "OK" {
				t.Skipf("Network is %q at baseline — nothing to protect on this fixture", baseV["Network"])
			}

			// Find the net/connectivity cache blob and empty it in place.
			blob := ""
			for b, key := range drp1CachedBlobSet(tree) {
				if key == "net/connectivity" {
					blob = b
					break
				}
			}
			if blob == "" {
				t.Skip("no net/connectivity cache recorded in this bundle")
			}
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(blob)), []byte{}, 0o600); err != nil {
				t.Fatalf("empty cache: %v", err)
			}

			b, err := source.Load(dir)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			results, insights, _ := replayBundle(b, false, true, false, false)
			got := verdictMap(results, insights)
			if got["Network"] == "OK" {
				t.Fatalf("FALSE-OK: Network was %s at baseline but replayed OK after emptying the net/connectivity cache — a lost derived-state probe must surface as not-measured, not healthy", baseV["Network"])
			}
		})
	}
}
