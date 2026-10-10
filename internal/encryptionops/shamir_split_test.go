package encryptionops

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

func TestShamirSplitWithConfig_ThresholdBelowTwoRefuses(t *testing.T) {
	chdirTemp(t)
	err := ShamirSplitWithConfig(5, 1, "")
	if err == nil {
		t.Fatal("expected refusal for threshold < 2")
	}
	if !strings.Contains(err.Error(), "--threshold") {
		t.Fatalf("expected a --threshold error, got: %v", err)
	}
}

func TestShamirSplitWithConfig_SharesBelowThresholdRefuses(t *testing.T) {
	chdirTemp(t)
	err := ShamirSplitWithConfig(2, 3, "")
	if err == nil {
		t.Fatal("expected refusal when shares < threshold")
	}
	if !strings.Contains(err.Error(), "--shares") {
		t.Fatalf("expected a --shares error, got: %v", err)
	}
}

// captureStderr is captureOutput's stderr counterpart — ShamirSplitWithConfig
// deliberately warns on stderr (not stdout) before printing shares, so the
// warning survives even if stdout alone is redirected.
func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	runErr := fn()
	os.Stderr = orig
	_ = w.Close()
	data := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, rerr := r.Read(buf)
		data = append(data, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	_ = r.Close()
	return string(data), runErr
}

func TestShamirSplitWithConfig_StdoutMode_WarnsOnStderrAndNeverPrintsKEK(t *testing.T) {
	chdirTemp(t)
	var stdout string
	stderr, err := captureStderr(t, func() error {
		var runErr error
		stdout, runErr = captureOutput(t, func() error {
			return ShamirSplitWithConfig(5, 3, "")
		})
		return runErr
	})
	if err != nil {
		t.Fatalf("ShamirSplitWithConfig: %v", err)
	}
	if !strings.Contains(stderr, "WARNING") {
		t.Fatal("expected a stderr warning before printing shares without --out-dir")
	}
	if strings.Contains(stdout, "shamir_commitment:") == false {
		t.Fatal("expected the commitment to be printed")
	}
}

func TestShamirSplitWithConfig_OutDir_WritesSharesWithRestrictivePermsAndReconstructs(t *testing.T) {
	dir := chdirTemp(t)
	outDir := filepath.Join(dir, "shares")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	stdout, err := captureOutput(t, func() error {
		return ShamirSplitWithConfig(5, 3, outDir)
	})
	if err != nil {
		t.Fatalf("ShamirSplitWithConfig: %v", err)
	}

	for i := 1; i <= 5; i++ {
		path := filepath.Join(outDir, "share-"+strconv.Itoa(i)+".hex")
		if mode := fileMode(t, path); mode != 0o600 {
			t.Fatalf("share file %s: expected mode 0600, got %v", path, mode)
		}
	}
	commitPath := filepath.Join(outDir, "commitment.hex")
	if _, err := os.Stat(commitPath); err != nil {
		t.Fatalf("expected commitment.hex to be written: %v", err)
	}

	re := regexp.MustCompile(`shamir_commitment: ([0-9a-f]+)`)
	m := re.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("could not find shamir_commitment in output:\n%s", stdout)
	}
	commitmentHex := m[1]

	// Property: threshold-of-N (3 of 5) shares reconstruct a valid 32-byte KEK.
	thresholdFiles := []string{
		filepath.Join(outDir, "share-1.hex"),
		filepath.Join(outDir, "share-2.hex"),
		filepath.Join(outDir, "share-3.hex"),
	}
	provider := crypto.NewShamirKeyProvider(thresholdFiles, nil, commitmentHex)
	kek, err := provider.KEK()
	if err != nil {
		t.Fatalf("expected threshold-of-N shares to reconstruct the KEK: %v", err)
	}
	if len(kek) != crypto.KEKSize {
		t.Fatalf("reconstructed KEK has wrong length: got %d, want %d", len(kek), crypto.KEKSize)
	}

	// Property: fewer than threshold (2 of 5) shares do NOT reconstruct it.
	belowThresholdFiles := []string{
		filepath.Join(outDir, "share-1.hex"),
		filepath.Join(outDir, "share-2.hex"),
	}
	belowProvider := crypto.NewShamirKeyProvider(belowThresholdFiles, nil, commitmentHex)
	if _, err := belowProvider.KEK(); err == nil {
		t.Fatal("expected sub-threshold shares to fail reconstruction")
	}
}
