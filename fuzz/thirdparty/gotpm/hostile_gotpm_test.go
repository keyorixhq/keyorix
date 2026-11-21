// Hostile-blob fuzz harness for google/go-tpm's tpm2 wire (un)marshalling.
//
// Keyorix call path (internal/crypto/tpm_provider.go): a TPM-sealed key blob is
// read from storage, json.Unmarshal'd into {Public, Private []byte}, and those
// two byte fields are handed to tpm2.Unmarshal[tpm2.TPM2BPublic] /
// tpm2.Unmarshal[tpm2.TPM2BPrivate]. The blob is attacker-controllable the
// moment storage is tampered with, so these Unmarshal calls parse untrusted
// bytes through the library's PUBLIC generic entry point.
//
// Oracles (sound only — every assertion operates on library outputs, no forged
// internal state):
//   - no panic: a panic inside tpm2.Unmarshal/Marshal fails the test (the go
//     fuzzer reports it as a crash).
//   - bounded work: a single Unmarshal of a <=64KiB input must return within a
//     generous wall budget; a timeout is a hang/CPU-DoS finding, not a flake,
//     because the input is tiny and the call is pure CPU.
//   - round-trip stability: if Unmarshal(data) succeeds, then re-Marshalling the
//     decoded value and decoding THAT must reproduce byte-identical output
//     (m1==m2). Sound because m1 is the library's own serialisation, so a second
//     decode must accept it and re-emit it unchanged; a mismatch is a
//     non-canonical / lossy codec defect.
//
// What these oracles do NOT verify: semantic correctness of the decoded TPM
// structures, that Keyorix's JSON layer is itself safe, allocation ceilings
// (relies on the go test fuzzer's own OOM detection, not a measured bound), or
// any behaviour of a real TPM transport.
package gotpmhostile

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// rt decodes data as T, and if that succeeds performs the round-trip-stability
// check. It returns a non-nil error only on an oracle violation (never on a
// plain decode failure, which is expected for hostile input).
func rt[T tpm2.Marshallable, P interface {
	*T
	tpm2.Unmarshallable
}](data []byte) error {
	v1, err := tpm2.Unmarshal[T, P](data)
	if err != nil {
		return nil
	}
	m1 := tpm2.Marshal(*v1)
	v2, err := tpm2.Unmarshal[T, P](m1)
	if err != nil {
		return fmt.Errorf("round-trip: library output failed to re-decode: %v (m1=%x)", err, m1)
	}
	m2 := tpm2.Marshal(*v2)
	if !bytes.Equal(m1, m2) {
		return fmt.Errorf("round-trip not stable: m1=%x m2=%x", m1, m2)
	}
	return nil
}

func FuzzGoTPMUnmarshal(f *testing.F) {
	// Seeds: minimal valid-ish TPM2B framings (2-byte big-endian size prefix).
	f.Add(uint8(0), []byte{0x00, 0x00})                         // empty TPM2B
	f.Add(uint8(1), []byte{0x00, 0x01, 0x00})                   // 1-byte buffer
	f.Add(uint8(2), []byte{0x00, 0x04, 0x00, 0x0b, 0x00, 0x22}) // TPMTPublic-ish
	f.Add(uint8(3), []byte{0x00, 0x20})
	f.Add(uint8(4), []byte{0xff, 0xff, 0x01, 0x02}) // lying size prefix
	f.Add(uint8(0), []byte{})

	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		errc := make(chan error, 1)
		go func() {
			var err error
			switch sel % 5 {
			case 0:
				err = rt[tpm2.TPM2BPublic](data)
			case 1:
				err = rt[tpm2.TPM2BPrivate](data)
			case 2:
				err = rt[tpm2.TPMTPublic](data)
			case 3:
				err = rt[tpm2.TPM2BData](data)
			case 4:
				err = rt[tpm2.TPM2BName](data)
			}
			errc <- err
		}()
		err, ok, fz := fuzzutil.Wait(errc, 15*time.Second)
		if !ok {
			t.Logf("stall monitor: process frozen %s of the wait window", fz)
			t.Fatalf("bounded-work: tpm2 did not return in 15s for %d-byte input sel=%d", len(data), sel%5)
		}
		if err != nil {
			t.Fatal(err)
		}
	})
}
