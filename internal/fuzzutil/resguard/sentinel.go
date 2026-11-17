package resguard

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
)

// Sentinel is the secret-leak oracle. It does NOT add a third marker-matching
// mechanism: it plants a unique sentinel value and then feeds every channel the
// Probe can see — log output, outbound network bytes, files written under
// TempDir, and any error/label string the harness hands it — through the
// existing taint package's sink (taint.Sink). Reusing taint means one needle
// set, one violation ledger and the same Allow/Expect rules the backupfmt and
// config taint harnesses already use; taint.Check(t.Fatalf) is the single
// verdict.
//
// Usage:
//
//	s := resguard.NewSentinel(net, logMeter, tmpDir)   // sets the taint marker
//	// ... in the harness, create a real secret whose value is s.Value() ...
//	taint.Reset()
//	// run the input; s.AttachNet/AttachLog scan wire & log automatically
//	s.ScanTempDir()           // scan files written this input
//	s.ScanString("error", err.Error())
//	taint.Check(t.Fatalf)     // fails if the sentinel reached any channel
//
// It scans only channels it is given: a secret written somewhere the Probe has
// no seam for (a third file tree, a syscall-level socket) is invisible. Stated
// so the oracle is never read as "proves the secret never leaked anywhere".
// The net hook scans each Write chunk on its own, so a sentinel split across
// two writes is missed, and over TLS it sees ciphertext, so it is blind to
// HTTPS payloads. No pilot wires the net hook yet.
type Sentinel struct {
	value   string
	tempDir string
}

// DefaultSentinel is a high-entropy lowercase-alphanumeric value (taint markers
// must be lowercase, since DNS and some parsers lowercase their input). It is
// fixed so fuzzing stays deterministic; override with a per-run value via
// NewSentinelValue if a run must not collide with corpus data.
const DefaultSentinel = "rsgsx7secretcanary9q"

// NewSentinel installs DefaultSentinel as the taint marker and wires the net and
// log meters' content hooks to scan for it. net and log may be nil.
func NewSentinel(net *NetMeter, log *LogMeter, tempDir string) *Sentinel {
	return NewSentinelValue(DefaultSentinel, net, log, tempDir)
}

// NewSentinelValue is NewSentinel with a caller-chosen sentinel value.
func NewSentinelValue(value string, net *NetMeter, log *LogMeter, tempDir string) *Sentinel {
	taint.SetMarker(value)
	// A secret leak is fatal in every channel class we route into taint.
	taint.SetFatal(taint.Log, taint.Host, taint.Path, taint.Query, taint.Command, taint.Template)
	s := &Sentinel{value: value, tempDir: tempDir}
	if net != nil {
		net.onWrite = func(b []byte) { taint.Sink(taint.Host, "resguard:net-out", string(b)) }
	}
	if log != nil {
		log.onWrite = func(b []byte) { taint.Sink(taint.Log, "resguard:log", string(b)) }
	}
	return s
}

// Value is the planted sentinel; the harness uses it as the secret's value.
func (s *Sentinel) Value() string { return s.value }

// ScanString routes one string (an error message, a metric label, a response
// body) through the taint sink under the given channel name.
func (s *Sentinel) ScanString(channel, str string) {
	taint.Sink(taint.Log, "resguard:"+channel, str)
}

// ScanTempDir reads every regular file under TempDir and scans its contents for
// the sentinel. Bounded by maxSentinelFileBytes per file so a huge artifact
// cannot blow memory; a secret in the first chunk is still caught. Symlinks are
// not followed.
func (s *Sentinel) ScanTempDir() {
	if s.tempDir == "" {
		return
	}
	// Walk and open through an os.Root so a symlink swapped in mid-walk cannot
	// redirect the open outside TempDir (gosec G122).
	root, err := os.OpenRoot(s.tempDir)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	_ = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		f, e := root.Open(p)
		if e != nil {
			return nil
		}
		defer func() { _ = f.Close() }()
		buf := make([]byte, maxSentinelFileBytes)
		n, _ := f.Read(buf)
		if n > 0 {
			taint.Sink(taint.Path, "resguard:file:"+filepath.Base(p), string(buf[:n]))
		}
		return nil
	})
}

const maxSentinelFileBytes = 1 << 20 // 1 MiB per file scanned
