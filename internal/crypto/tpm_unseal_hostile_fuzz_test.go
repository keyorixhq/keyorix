package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	tpmCCLoad   = 0x00000157
	tpmCCUnseal = 0x0000015E

	tpmSTNoSessions = 0x8001
	tpmSTSessions   = 0x8002

	// tpmUnsealTimeCap bounds one unseal against the in-process simulator. A
	// healthy round (CreatePrimary, Load, Unseal, two flushes) takes milliseconds.
	tpmUnsealTimeCap = 5 * time.Second
)

// hostileTPM forwards every command to the real simulator and hands the
// provider a mutated response for one chosen command code: it models a TPM (or
// a resource manager, or a tampered /dev/tpmrm0 path) that answers with bytes
// the TPM never produced. It records the command it mutated and the response
// it returned, so the oracle can parse them independently.
type hostileTPM struct {
	inner    transport.TPM
	targetCC uint32
	mutate   func([]byte) []byte

	sentCmd []byte
	gotRsp  []byte
}

func (h *hostileTPM) Send(cmd []byte) ([]byte, error) {
	rsp, err := h.inner.Send(cmd)
	if err != nil || len(cmd) < 10 || binary.BigEndian.Uint32(cmd[6:10]) != h.targetCC {
		return rsp, err
	}
	out := h.mutate(append([]byte(nil), rsp...))
	h.sentCmd = append([]byte(nil), cmd...)
	h.gotRsp = append([]byte(nil), out...)
	return out, nil
}

func (h *hostileTPM) Close() error { return nil }

// applyTPMMutation interprets ops as a mutation of rsp. ops[0] picks the mode:
// 0 xor (pos,val) pairs, 1 truncate, 2 append, 3 replace the whole response.
func applyTPMMutation(ops []byte) func([]byte) []byte {
	return func(rsp []byte) []byte {
		if len(ops) == 0 {
			return rsp
		}
		arg := ops[1:]
		switch ops[0] % 4 {
		case 0:
			if len(rsp) == 0 {
				return rsp
			}
			for i := 0; i+1 < len(arg); i += 2 {
				rsp[int(arg[i])%len(rsp)] ^= arg[i+1]
			}
			return rsp
		case 1:
			n := 0
			if len(arg) > 0 {
				n = int(arg[0])
			}
			return rsp[:min(n, len(rsp))]
		case 2:
			return append(rsp, arg...)
		default:
			return append([]byte(nil), arg...)
		}
	}
}

// parseUnsealResponse is an independent, spec-direct reader of a
// TPM2_Unseal response (TPM 2.0 Part 3 §12.7: no response handles, one
// TPM2B_SENSITIVE_DATA parameter). Whether the response has a parameterSize
// field is decided by the COMMAND's tag (Part 1 §18.4: a successful response
// carries TPM_ST_SESSIONS exactly when the command did). It returns the
// outData TPM2B, the response code, and whether a TPM2B could be located.
func parseUnsealResponse(cmd, rsp []byte) (out []byte, rc uint32, ok bool) {
	if len(rsp) < 10 || len(cmd) < 2 {
		return nil, 0, false
	}
	rc = binary.BigEndian.Uint32(rsp[6:10])
	if rc != 0 {
		return nil, rc, false
	}
	params := rsp[10:]
	if binary.BigEndian.Uint16(cmd[0:2]) == tpmSTSessions {
		if len(params) < 4 {
			return nil, rc, false
		}
		ps := binary.BigEndian.Uint32(params[0:4])
		if uint64(ps) > uint64(len(params)-4) {
			return nil, rc, false
		}
		params = params[4 : 4+ps]
	}
	if len(params) < 2 {
		return nil, rc, false
	}
	n := int(binary.BigEndian.Uint16(params[0:2]))
	if 2+n > len(params) {
		return nil, rc, false
	}
	return params[2 : 2+n], rc, true
}

// tpmShortParams is the named exception for finding TP1-TPM-short-params
// (pinned by TestTPMFindingShortParamsAreSuccess): go-tpm v0.9.8's rspParameters
// returns success without decoding anything when the parameter area is shorter
// than 2 bytes, so Unseal reports an empty outData. It is excused at the go-tpm
// level (H1) only; the keyorix-level oracle K1 has no exception.
func tpmShortParams(cmd, rsp []byte) bool {
	if len(rsp) < 10 {
		return false
	}
	params := rsp[10:]
	if len(cmd) >= 2 && binary.BigEndian.Uint16(cmd[0:2]) == tpmSTSessions {
		if len(params) < 4 {
			return false
		}
		ps := binary.BigEndian.Uint32(params[0:4])
		if uint64(ps) > uint64(len(params)-4) {
			return false
		}
		params = params[4 : 4+ps]
	}
	return len(params) < 2
}

// FuzzTPMUnsealHostileResponse drives the TPM KEK provider's real unseal path
// (TPMKeyProvider.unseal, then validateKEK exactly as KEK() does) against the
// go-tpm-tools simulator, with one TPM response (Unseal, or Load) replaced by a
// fuzzer-mutated one. The TPM is the provider's root of trust, so a hostile TPM
// can always hand back a key of its choosing; what this target pins is that
// go-tpm's response parsing reports what the response actually says.
//
//   - H1 VALUE (go-tpm level): when unseal returns outData without error, the
//     independent reader parseUnsealResponse locates a TPM2B in the mutated
//     response and it is byte-identical to outData.
//   - H2 RESPONSE CODE: a mutated Unseal response whose responseCode is non-zero
//     never yields a key.
//   - K1 KEK (keyorix level, no exceptions): when unseal plus validateKEK accept a
//     key, the mutated response is well-formed by the independent reader, has
//     responseCode 0, and the key is that response's outData.
//   - H3 BOUNDED TIME: one unseal returns within tpmUnsealTimeCap.
//   - CONTROL: an empty mutation must unseal the sealed KEK (checked on every
//     iteration with no ops, so a broken harness cannot pass vacuously).
//
// What this does NOT verify: the response header's tag and responseSize fields
// and trailing bytes after the parameter or session area (go-tpm does not check
// the first two; pinned by TestTPMFindingResponseHeaderUnchecked); session HMACs
// (the provider uses password sessions, which carry none); that a key a hostile
// TPM returns is the sealed one (impossible by construction: the TPM is trusted);
// Load-response handle confusion beyond "the unseal still fails or returns a
// consistent value"; the real /dev/tpmrm0 transport and kernel resource manager;
// PCR policy (the provider seals with no PCR policy, see tpm_provider.go).
func FuzzTPMUnsealHostileResponse(f *testing.F) {
	var sim *simulator.Simulator
	f.Cleanup(func() {
		if sim != nil {
			_ = sim.Close()
		}
	})
	var sealed tpmSealedBlob
	var want []byte

	f.Add(byte(0), []byte{})                                               // control: no mutation
	f.Add(byte(0), []byte{0, 9, 0x01})                                     // flip a response-code bit
	f.Add(byte(0), []byte{0, 12, 0x01, 13, 0x07})                          // corrupt parameterSize
	f.Add(byte(0), []byte{1, 14})                                          // truncate into the parameters
	f.Add(byte(0), []byte{2, 0xAA, 0xBB})                                  // trailing bytes
	f.Add(byte(0), []byte{3, 0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0, 0, 0, 0}) // replace: empty TPM2B
	f.Add(byte(1), []byte{0, 11, 0x01})                                    // Load: flip a handle bit
	f.Add(byte(0), []byte{0, 16, 0x01})                                    // valid response, different outData
	// Empty parameter area with a valid password-session area (TP1-TPM-short-params).
	f.Add(byte(0), []byte{3, 0x80, 0x02, 0, 0, 0, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0})

	f.Fuzz(func(t *testing.T, which byte, ops []byte) {
		if len(ops) > 512 {
			return
		}
		if sim == nil {
			s, err := simulator.GetWithFixedSeedInsecure(4242)
			if err != nil {
				t.Fatalf("harness: simulator: %v", err)
			}
			sim = s
			seal := &TPMKeyProvider{open: func() (transport.TPMCloser, error) {
				return &hostileTPM{inner: transport.FromReadWriter(sim), mutate: func(b []byte) []byte { return b }}, nil
			}}
			want = bytes.Repeat([]byte{0x5A}, KEKSize)
			b, err := seal.seal(want)
			if err != nil {
				t.Fatalf("harness: seal: %v", err)
			}
			sealed = b
		}
		target := uint32(tpmCCUnseal)
		if which%2 == 1 {
			target = tpmCCLoad
		}
		h := &hostileTPM{inner: transport.FromReadWriter(sim), targetCC: target, mutate: applyTPMMutation(ops)}
		p := &TPMKeyProvider{open: func() (transport.TPMCloser, error) { return h, nil }}
		defer flushTransients(t, sim)

		start := time.Now()
		out, err := p.unseal(sealed)
		if d := time.Since(start); d > tpmUnsealTimeCap {
			t.Fatalf("H3 BOUNDED TIME: unseal took %v (cap %v), ops=%x", d, tpmUnsealTimeCap, ops)
		}
		if len(ops) == 0 {
			if err != nil || !bytes.Equal(out, want) {
				t.Fatalf("CONTROL: unmutated unseal returned %x, %v; want the sealed KEK", out, err)
			}
			return
		}
		checkHostileUnseal(t, target, h, out, err)
	})
}

func checkHostileUnseal(t *testing.T, target uint32, h *hostileTPM, out []byte, err error) {
	t.Helper()
	kek, kerr := []byte(nil), err
	if err == nil {
		kek, kerr = validateKEK(out, "tpm")
	}
	if target != tpmCCUnseal || h.gotRsp == nil {
		// Load was mutated (or Unseal never ran): the Unseal response is genuine
		// simulator output, so only K1's "key came from a successful Unseal"
		// side is checkable, and it holds by construction. H3 already ran.
		return
	}
	pOut, rc, ok := parseUnsealResponse(h.sentCmd, h.gotRsp)
	if rc != 0 && (err == nil || kerr == nil) {
		t.Fatalf("H2 RESPONSE CODE: response code %#x but unseal returned %x without error\n rsp=%x", rc, out, h.gotRsp)
	}
	if err == nil && !(len(out) == 0 && tpmShortParams(h.sentCmd, h.gotRsp)) {
		if !ok || !bytes.Equal(pOut, out) {
			t.Fatalf("H1 VALUE: go-tpm returned outData %x; independent reader found %x (ok=%v)\n cmd=%x\n rsp=%x", out, pOut, ok, h.sentCmd, h.gotRsp)
		}
	}
	if kerr == nil {
		if !ok || rc != 0 || !bytes.Equal(pOut, kek) {
			t.Fatalf("K1 KEK: provider accepted KEK %x from a response the independent reader reads as %x (ok=%v rc=%#x)\n rsp=%x", kek, pOut, ok, rc, h.gotRsp)
		}
	}
}

// flushTransients flushes every transient object left in the simulator, so an
// iteration whose mutated Load response lied about the handle does not leak the
// real object and exhaust the simulator's three object slots for the next one.
func flushTransients(t *testing.T, sim *simulator.Simulator) {
	t.Helper()
	tpm := transport.FromReadWriter(sim)
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 16,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("harness: list transient handles: %v", err)
	}
	hs, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatalf("harness: decode handle list: %v", err)
	}
	for _, hd := range hs.Handle {
		_, _ = tpm2.FlushContext{FlushHandle: hd}.Execute(tpm)
	}
}
