package encryption

// atrest_memory_canary_fuzz_test.go — NR1: "where can a secret rest or linger
// that it should not?" applied to KEY MATERIAL (DEK/KEK), the one class of
// secret the existing canary family (secret_ops_canary_fuzz_test.go,
// canary_sweep_core_test.go, cli_args_canary_fuzz_test.go) never plants or
// scans for. Those targets scan the SQLite file, -wal, DB cells, os.TempDir,
// logs and responses for secret VALUES; none tracks the raw DEK/KEK bytes, and
// none scans process MEMORY.
//
// This target drives a random key-lifecycle sequence (Initialize, encrypt
// secrets, RotateDEKWithSweep, RotateKEKPassphrase, RewrapDEKWithProvider,
// Shutdown) and, with the exact bytes of every DEK generation and every KEK it
// can compute or control, checks two properties the codebase asserts but had no
// byte-level fuzzer for:
//
//   Part A (at rest). ADR-004: "Never: raw KEK on disk." The wrapped DEK on disk
//   (dek.key) is ciphertext, so the RAW DEK bytes must appear nowhere on disk,
//   and a passphrase-derived KEK (never persisted) likewise. A file-provider KEK
//   is legitimately at rest in exactly one place: the operator's own key file.
//   Oracle: a tracked key value found anywhere on disk other than its single
//   allow-path is a finding. Secret VALUES are tracked too (bonus coverage:
//   they too must never rest in plaintext), though that overlaps the existing
//   targets by design.
//
//   Part B (in memory). INV-ENCRYPTION-24 claims EncryptionService.dek is wiped
//   on Shutdown. That is the authoritative, machine-checked, NARROW claim — this
//   target re-asserts it (IsDEKWiped) as a hard oracle. A broader heap-dump scan
//   for surviving key bytes is EXPLORATORY ONLY and never fails the fuzzer: in
//   Go it cannot be a defect absent a documented zeroization claim for that
//   specific copy (GC relocates/duplicates slices, strings are immutable,
//   finalizers run at GC's discretion, and WriteHeapDump's coverage of
//   unreachable-but-unswept memory is a runtime implementation detail).
//
// Red/green proof lives in atrest_memory_canary_selftest_test.go: it plants a
// DEK on disk, a KEK outside its allow-path, and a live in-memory key, and
// asserts each oracle fires, then that a clean world passes.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// ─── tracked key material ────────────────────────────────────────────────────

// tracked is one secret value whose raw bytes must rest nowhere on disk except
// allowPath ("" meaning nowhere at all). DEKs and passphrase-derived KEKs have
// allowPath=="" (never persisted); a file-provider KEK's allowPath is its own
// key file.
type tracked struct {
	label     string
	raw       []byte
	allowPath string // absolute path where this value legitimately rests, or ""
}

// atRestWindow is the smallest raw-byte run treated as a (truncated) key leak.
// 16 bytes = 128 bits: a chance match against real file bytes is negligible,
// while half a leaked 32-byte key is still caught.
const atRestWindow = 16

// encodingsOf returns the on-disk byte forms an at-rest scan must catch for a
// raw key: the value itself, its hex (both cases) and its base64 in the four
// standard alphabets — the realistic ways key bytes get written to a file, a
// log line or a JSON blob. A 16-byte raw prefix is added as a truncation guard.
func encodingsOf(raw []byte) []struct {
	name string
	b    []byte
} {
	type nb = struct {
		name string
		b    []byte
	}
	out := []nb{
		{"raw", raw},
		{"hex-lower", []byte(hex.EncodeToString(raw))},
		{"hex-upper", []byte(strings.ToUpper(hex.EncodeToString(raw)))},
		{"b64-std", []byte(base64.StdEncoding.EncodeToString(raw))},
		{"b64-url", []byte(base64.URLEncoding.EncodeToString(raw))},
		{"b64-rawstd", []byte(base64.RawStdEncoding.EncodeToString(raw))},
		{"b64-rawurl", []byte(base64.RawURLEncoding.EncodeToString(raw))},
	}
	if len(raw) >= atRestWindow {
		out = append(out, nb{"raw-window16", raw[:atRestWindow]})
	}
	return out
}

// finding is one at-rest leak: a tracked value's encoding found in a file that
// is not its allow-path.
type finding struct {
	file     string
	label    string
	encoding string
	offset   int
}

func (fd finding) String() string {
	return fd.file + " contains " + fd.label + " (" + fd.encoding + ") at offset " +
		itoa(fd.offset)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// scanFileForKeys reads path and reports every tracked value (in any encoding)
// found in it, except where path IS that value's allow-path.
func scanFileForKeys(path string, ts []tracked) []finding {
	const maxFile = 64 << 20
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > maxFile {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []finding
	for _, tr := range ts {
		if len(tr.raw) == 0 {
			continue
		}
		if sameFile(path, tr.allowPath) {
			continue
		}
		seen := false
		for _, enc := range encodingsOf(tr.raw) {
			if len(enc.b) < 8 {
				continue
			}
			if off := indexBytes(data, enc.b); off >= 0 {
				out = append(out, finding{file: path, label: tr.label, encoding: enc.name, offset: off})
				seen = true
				break // one finding per (file,value) is enough to flag it
			}
		}
		_ = seen
	}
	return out
}

func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ap, err1 := filepath.Abs(a)
	bp, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return ap == bp
}

// indexBytes finds needle in hay (optimized substring search). The length guard
// is kept explicit: an empty/over-long needle never matches.
func indexBytes(hay, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(hay) {
		return -1
	}
	return bytes.Index(hay, needle)
}

// ─── the lifecycle world under test ──────────────────────────────────────────

// keyWorld drives the key lifecycle and accumulates the tracked key material.
//
// The KEK is sourced by a FILE key provider throughout — the real production
// path (ADR-038; keymanager_lifecycle.go notes the legacy passphrase+salt
// derivation is "unreachable from any live production caller today"). Using a
// file provider makes the exact KEK bytes trackable AND avoids a 600k-iteration
// PBKDF2 on every exec, so the fuzzer actually gets throughput.
type keyWorld struct {
	t   *testing.T
	svc *Service
	dir string
	db  *gorm.DB

	curKEKPath string          // allow-path of the current file-provider KEK
	tracked    []tracked       // every DEK/KEK/secret value ever live
	seenRaw    map[string]bool // dedup of tracked raw bytes
	tmpBefore  map[string]bool // os.TempDir entries present before the run
}

// initKEKIndex seeds the first KEK; rewraps use the op loop index (0..23), so an
// init KEK can never collide with a rewrap KEK (which would false-positive the
// allow-path check when the same bytes legitimately rest in two provider files).
const initKEKIndex = 9000

func newKeyWorld(t *testing.T) *keyWorld {
	t.Helper()
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "provider-init.kek")
	if err := os.WriteFile(kekPath, []byte(hex.EncodeToString(deriveControlledKEK(initKEKIndex))), 0o600); err != nil {
		t.Fatalf("write init kek: %v", err)
	}
	cfg := &config.EncryptionConfig{
		Enabled:     true,
		DEKPath:     "dek.key",
		SaltPath:    "kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: kekPath},
	}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(""); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "secrets.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	for _, m := range []any{
		&models.SecretNode{}, &models.SecretVersion{}, &models.Session{},
		&models.APIToken{}, &models.APIClient{}, &models.PasswordReset{},
		&models.MFASecret{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.NotificationChannel{}, &models.SystemMetadata{},
	} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	w := &keyWorld{
		t: t, svc: svc, dir: dir, db: db,
		curKEKPath: kekPath,
		seenRaw:    map[string]bool{},
		tmpBefore:  listTmp(),
	}
	w.recordKEK()
	w.recordDEK()
	return w
}

func listTmp() map[string]bool {
	m := map[string]bool{}
	ents, err := os.ReadDir(os.TempDir())
	if err != nil {
		return m
	}
	for _, e := range ents {
		m[e.Name()] = true
	}
	return m
}

// recordDEK captures the current DEK generation's raw bytes.
func (w *keyWorld) recordDEK() {
	dek := w.svc.keyManager.GetDEK()
	w.addTracked(tracked{label: "DEK", raw: dek, allowPath: ""})
}

// recordKEK captures the current file-provider KEK's raw bytes — the exact
// bytes written to the provider file, which is that value's single legitimate
// at-rest location (allow-path).
func (w *keyWorld) recordKEK() {
	raw, err := readHexKEKFile(w.curKEKPath)
	if err == nil {
		w.addTracked(tracked{label: "KEK-file", raw: raw, allowPath: w.curKEKPath})
	}
}

func readHexKEKFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(b)))
}

func (w *keyWorld) addTracked(tr tracked) {
	if len(tr.raw) == 0 || isAllZero(tr.raw) {
		return
	}
	key := tr.label + "|" + string(tr.raw)
	if w.seenRaw[key] {
		return
	}
	w.seenRaw[key] = true
	w.tracked = append(w.tracked, tr)
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// atRestFindings scans every key-dir file, the DB and its sidecars, and any new
// os.TempDir entry our process produced, for tracked key material out of place.
func (w *keyWorld) atRestFindings() []finding {
	var out []finding
	seenPath := map[string]bool{}
	walk := func(root string) {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || seenPath[p] {
				return nil
			}
			seenPath[p] = true
			out = append(out, scanFileForKeys(p, w.tracked)...)
			return nil
		})
	}
	walk(w.dir)
	// New top-level os.TempDir entries this process produced (bounded: only the
	// delta, so we never scan other sessions' shared-tmp data).
	if ents, err := os.ReadDir(os.TempDir()); err == nil {
		for _, e := range ents {
			if w.tmpBefore[e.Name()] || e.IsDir() {
				continue
			}
			p := filepath.Join(os.TempDir(), e.Name())
			if !seenPath[p] {
				seenPath[p] = true
				out = append(out, scanFileForKeys(p, w.tracked)...)
			}
		}
	}
	return out
}

// step applies one operation selected by op. Errors are non-fatal: an op that
// refuses just leaves the world unchanged.
func (w *keyWorld) step(op byte, idx int) {
	switch op % 3 {
	case 0: // encrypt a secret value into the DB (bonus secret-value coverage)
		val := []byte("nr1-secret-" + itoa(idx) + "-" + hex.EncodeToString([]byte{op}))
		aad := SecretAAD(uint(idx+1), 1, idx+1)
		enc, meta, err := w.svc.EncryptSecretWithAAD(val, aad)
		if err != nil {
			return
		}
		w.addTracked(tracked{label: "secret-value", raw: val, allowPath: ""})
		_ = w.db.Create(&models.SecretVersion{
			SecretNodeID:       uint(idx + 1),
			VersionNumber:      idx + 1,
			EncryptedValue:     enc,
			EncryptionMetadata: models.JSON(meta),
		}).Error
	case 1: // rotate the DEK with a full re-encryption sweep (new DEK, same KEK)
		if _, err := w.svc.RotateDEKWithSweep("", w.db); err != nil {
			return
		}
		w.recordDEK()
	case 2: // migrate the KEK to a NEW file provider with bytes we control
		kekPath := filepath.Join(w.dir, "provider-"+itoa(idx)+".kek")
		raw := deriveControlledKEK(idx)
		if err := os.WriteFile(kekPath, []byte(hex.EncodeToString(raw)), 0o600); err != nil {
			return
		}
		if err := w.svc.RewrapDEKWithProvider(crypto.NewFileKeyProvider(kekPath)); err != nil {
			return
		}
		w.curKEKPath = kekPath
		w.recordKEK()
	}
}

// deriveControlledKEK produces a deterministic, known 32-byte KEK for a
// file-provider migration, so its exact bytes are trackable at rest.
func deriveControlledKEK(idx int) []byte {
	raw := make([]byte, crypto.KEKSize)
	for i := range raw {
		raw[i] = byte((idx*31 + i*7 + 0x5a) & 0xff)
	}
	// Avoid an all-zero or low-entropy run that could coincide with file padding.
	raw[0] |= 0x80
	raw[len(raw)-1] |= 0x01
	return raw
}

// finishAndCheckMemory shuts the service down and returns the narrow
// documented-claim result (IsDEKWiped) plus the exploratory heap-dump hit
// count. The heap count is informational only.
func (w *keyWorld) finishAndCheckMemory() (dekWiped bool, heapHits int) {
	es := w.svc.encryptionService
	w.svc.Shutdown()
	if es != nil {
		dekWiped = es.IsDEKWiped()
	} else {
		dekWiped = true
	}
	heapHits = w.heapDumpHits()
	return dekWiped, heapHits
}

// heapDumpHits GCs, writes a heap dump and counts tracked key values (raw or
// 16-byte window) surviving in it. EXPLORATORY: see the file header for why a
// positive here is not, by itself, a defect in Go.
func (w *keyWorld) heapDumpHits() int {
	f, err := os.CreateTemp(w.dir, "nr1-heap-*.dump")
	if err != nil {
		return -1
	}
	defer os.Remove(f.Name())
	runtime.GC()
	debug.WriteHeapDump(f.Fd())
	_ = f.Close()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		return -1
	}
	hits := 0
	for _, tr := range w.tracked {
		if tr.label != "DEK" && tr.label != "KEK-file" {
			continue
		}
		if len(tr.raw) >= atRestWindow && indexBytes(data, tr.raw[:atRestWindow]) >= 0 {
			hits++
		}
	}
	return hits
}

// ─── the fuzzer ──────────────────────────────────────────────────────────────

// FuzzAtRestKeyMaterial drives a random key-lifecycle sequence and asserts no
// DEK/KEK (or secret value) bytes rest on disk out of place, and that the
// documented DEK wipe-on-shutdown holds.
func FuzzAtRestKeyMaterial(f *testing.F) {
	// Ops: 0=encrypt secret, 1=rotate DEK (sweep), 2=migrate KEK (new file provider).
	f.Add([]byte{0})       // encrypt one secret
	f.Add([]byte{0, 1})    // encrypt, rotate DEK
	f.Add([]byte{0, 2})    // encrypt, migrate KEK
	f.Add([]byte{0, 2, 1}) // encrypt, migrate KEK, rotate DEK
	f.Add([]byte{2, 1, 0, 2})
	f.Add([]byte{0, 1, 2, 1, 2, 1})

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 24 {
			ops = ops[:24] // bound sequence length; longer adds cost, not coverage
		}
		w := newKeyWorld(t)
		for i, op := range ops {
			w.step(op, i)
			if fs := w.atRestFindings(); len(fs) > 0 {
				for _, fd := range fs {
					t.Errorf("AT-REST LEAK after op %d: %s", i, fd.String())
				}
				return
			}
		}
		// Final scan (covers .pending/.lock remnants left by the last op).
		for _, fd := range w.atRestFindings() {
			t.Errorf("AT-REST LEAK (final): %s", fd.String())
		}

		dekWiped, heapHits := w.finishAndCheckMemory()
		if !dekWiped {
			// INV-ENCRYPTION-24: a genuine, documented-claim violation.
			t.Errorf("MEMORY: EncryptionService.dek NOT wiped after Shutdown (INV-ENCRYPTION-24 violated)")
		}
		// heapHits is exploratory/HARDENING only — never fails the fuzzer.
		_ = heapHits
	})
}
