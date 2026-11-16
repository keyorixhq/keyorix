package resguard

import (
	"sync/atomic"

	"github.com/keyorixhq/keyorix/internal/kdfmeter"
)

// KDFMeter is the password-hash / key-derivation cost seam: it counts the bcrypt
// (and any other kdfmeter-wrapped) invocations a single logical operation makes,
// split into GenerateFromPassword vs CompareHashAndPassword. It is the counterpart
// to DBMeter for a DIFFERENT resource: a KDF call costs milliseconds of CPU, and
// an account-enumeration timing side-channel lives precisely in whether that cost
// is spent the SAME number of times for an account that exists and one that does
// not. DBQueries cannot see this — a path can be perfectly DB-balanced yet
// KDF-unbalanced, which is the enumeration bug — so KDF invocations are metered
// separately.
//
// It reads the production seam internal/kdfmeter by installing a cheap observer
// (two atomic adds). Install it once per process with Install(); the Probe reads
// and resets it per input. Like the kdfmeter seam itself, it counts only
// invocations routed THROUGH internal/kdfmeter — a credential path that calls
// golang.org/x/crypto/bcrypt directly is invisible to it (which is itself a
// finding: a bypass of the shared wrapper). Stated so KDFGenerates/KDFCompares
// read as "wrapped KDF calls", not "all hashing work".
type KDFMeter struct {
	generates atomic.Int64
	compares  atomic.Int64
}

// NewKDFMeter returns a KDFMeter not yet installed as the kdfmeter observer.
func NewKDFMeter() *KDFMeter { return &KDFMeter{} }

func (m *KDFMeter) reset() { m.generates.Store(0); m.compares.Store(0) }

func (m *KDFMeter) read() (generates, compares int) {
	return int(m.generates.Load()), int(m.compares.Load())
}

// Install registers this meter as the process-global kdfmeter observer and
// returns the previously-installed observer, which the caller should restore via
// tb.Cleanup(func(){ kdfmeter.SetObserver(prev) }). Install exactly once per
// process (the stock fuzz engine runs one body at a time per process, so one
// KDFMeter per testing.F is correct for -parallel too — -parallel forks
// processes).
func (m *KDFMeter) Install() func(kdfmeter.Op) {
	return kdfmeter.SetObserver(func(op kdfmeter.Op) {
		switch op {
		case kdfmeter.OpGenerate:
			m.generates.Add(1)
		case kdfmeter.OpCompare:
			m.compares.Add(1)
		}
	})
}

// Generates/Compares/Total expose live totals outside the Probe.
func (m *KDFMeter) Generates() int { return int(m.generates.Load()) }
func (m *KDFMeter) Compares() int  { return int(m.compares.Load()) }
func (m *KDFMeter) Total() int     { return int(m.generates.Load() + m.compares.Load()) }
