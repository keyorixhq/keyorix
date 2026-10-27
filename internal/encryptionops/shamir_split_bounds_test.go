package encryptionops

// REVIEW-ENCRYPTIONOPS-1 R5: shamir-split refuses out-of-range --shares and
// --threshold before it allocates output names or looks at --out-dir.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shamirSplitNoPanic(shares, threshold int, outDir string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panicked: %v", r)
		}
	}()
	return ShamirSplitWithConfig(shares, threshold, outDir)
}

func TestShamirSplitWithConfig_TooManySharesRefusedBeforeTheOutputDirectory(t *testing.T) {
	for _, shares := range []int{256, 1 << 50} {
		// An --out-dir that already holds share-1.hex: the old code looked at it
		// (one Lstat per share) before the share count was ever checked.
		outDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(outDir, "share-1.hex"), []byte("a share the server uses"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := shamirSplitNoPanic(shares, 2, outDir)
		if err == nil {
			t.Fatalf("--shares %d was accepted", shares)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("--shares (%d) must be at most 255", shares)) {
			t.Fatalf("--shares %d: expected the up-front bound refusal, got: %v", shares, err)
		}
		entries, rerr := os.ReadDir(outDir)
		if rerr != nil || len(entries) != 1 {
			t.Fatalf("--shares %d touched --out-dir: %v %v", shares, entries, rerr)
		}
	}
	// Without --out-dir as well (stdout mode).
	if err := shamirSplitNoPanic(1<<50, 2, ""); err == nil || !strings.Contains(err.Error(), "must be at most 255") {
		t.Fatalf("stdout mode: expected the bound refusal, got: %v", err)
	}
}

func TestShamirSplitWithConfig_ThresholdBelowOneRefusedBeforeTheOutputDirectory(t *testing.T) {
	for _, threshold := range []int{0, -1} {
		outDir := filepath.Join(t.TempDir(), "never-created")
		err := shamirSplitNoPanic(3, threshold, outDir)
		if err == nil || !strings.Contains(err.Error(), "--threshold must be at least 2") {
			t.Fatalf("--threshold %d: expected the threshold refusal, got: %v", threshold, err)
		}
		if _, serr := os.Lstat(outDir); !os.IsNotExist(serr) {
			t.Fatalf("--threshold %d created --out-dir: %v", threshold, serr)
		}
	}
}

// The bound is exact: 255 shares is still a valid split.
func TestShamirSplitWithConfig_255SharesStillSplit(t *testing.T) {
	outDir := t.TempDir()
	if _, err := captureOutput(t, func() error { return ShamirSplitWithConfig(255, 2, outDir) }); err != nil {
		t.Fatalf("255 shares: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "share-255.hex")); err != nil {
		t.Fatalf("share-255.hex not written: %v", err)
	}
}
