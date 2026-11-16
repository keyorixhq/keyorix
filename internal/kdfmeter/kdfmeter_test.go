package kdfmeter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/kdfmeter"
)

// TestKDFMeter_CountsGenerateAndCompare is the red/green proof that the seam
// counts. With an observer installed, each GenerateFromPassword yields exactly
// one OpGenerate and each CompareHashAndPassword exactly one OpCompare; with the
// observer uninstalled, the counters do not move (zero behaviour change when off).
func TestKDFMeter_CountsGenerateAndCompare(t *testing.T) {
	var gen, cmp int
	prev := kdfmeter.SetObserver(func(op kdfmeter.Op) {
		switch op {
		case kdfmeter.OpGenerate:
			gen++
		case kdfmeter.OpCompare:
			cmp++
		}
	})
	t.Cleanup(func() { kdfmeter.SetObserver(prev) })

	hash, err := kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("pw")); err != nil {
		t.Fatalf("compare (correct): %v", err)
	}
	// A wrong password still costs exactly one compare — the property the
	// enumeration oracle leans on.
	_ = kdfmeter.CompareHashAndPassword(hash, []byte("wrong"))

	if gen != 1 {
		t.Fatalf("OpGenerate count = %d, want 1", gen)
	}
	if cmp != 2 {
		t.Fatalf("OpCompare count = %d, want 2", cmp)
	}

	// Uninstall: counters must freeze. This is the "zero behaviour change when
	// off" half — a guard nobody has watched stay still is not a guard.
	kdfmeter.SetObserver(nil)
	if _, err := kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost); err != nil {
		t.Fatalf("generate (observer off): %v", err)
	}
	_ = kdfmeter.CompareHashAndPassword(hash, []byte("pw"))
	if gen != 1 || cmp != 2 {
		t.Fatalf("counters moved with observer off: gen=%d cmp=%d", gen, cmp)
	}
}

// TestKDFMeter_BehaviourIdenticalToBcrypt confirms the wrapper is a pass-through:
// the hash it produces verifies, and a wrong password fails, exactly as the raw
// library would — so routing production through it changes nothing observable.
func TestKDFMeter_BehaviourIdenticalToBcrypt(t *testing.T) {
	hash, err := kdfmeter.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("correct horse")); err != nil {
		t.Fatalf("raw bcrypt must verify a kdfmeter-produced hash: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("correct horse")); err != nil {
		t.Fatalf("kdfmeter must verify its own hash: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("wrong")); err == nil {
		t.Fatal("wrong password must fail")
	}
}

// TestKDFMeterSetObserver_NoProductionCallers fails the build if any non-_test.go
// file in the repo calls kdfmeter.SetObserver. Enablement is test-only: the only
// legitimate caller is the resguard KDFMeter from a _test.go file. This is the
// machine-checked guard that keeps the seam zero-cost in production.
func TestKDFMeterSetObserver_NoProductionCallers(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" || name == ".scratch" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// internal/fuzzutil/resguard is a test-only helper package (NOT a _test.go
		// file, but its test-only status is itself machine-enforced by
		// TestResguardImportedOnlyFromTests — nothing outside *_test.go may import
		// it). Its KDFMeter.Install legitimately calls kdfmeter.SetObserver to wire
		// the counter. Excluded here BY PACKAGE PATH, not by call shape, so the
		// exclusion is a checkable constant and stays sound if the installer moves
		// between files within that package.
		if strings.Contains(filepath.ToSlash(path), "internal/fuzzutil/resguard/") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), "kdfmeter.SetObserver") {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("kdfmeter.SetObserver is test-only but is called from production file(s): %s", strings.Join(offenders, ", "))
	}
}

// repoRoot walks up from the package dir to the module root (the dir with go.mod).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from package dir")
		}
		dir = parent
	}
}
