package verifierflip_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption/aead"
	"github.com/keyorixhq/keyorix/internal/pqwrap"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
	"github.com/keyorixhq/keyorix/internal/verifierflip"
	"github.com/keyorixhq/keyorix/pkg/licenseverify"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

// ---- shared helpers ------------------------------------------------------

func fixedKey(label string) []byte {
	h := sha256.Sum256([]byte("verifierflip/" + label))
	return h[:]
}

func hmacHex(key []byte, parts ...[]byte) string {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// jsonRegion maps a byte offset of a compact JSON document to the nearest
// preceding object key, so reports group by field.
func jsonRegion(doc []byte) func(int) string {
	reg := make([]string, len(doc))
	cur := "<start>"
	inStr, esc := false, false
	start := 0
	for i, c := range doc {
		reg[i] = cur
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
				j := i + 1
				if j < len(doc) && doc[j] == ':' {
					cur = string(doc[start+1 : i])
					for k := start; k <= i; k++ {
						reg[k] = "key:" + cur
					}
				}
			}
			continue
		}
		if c == '"' {
			inStr, start = true, i
		}
	}
	return func(off int) string {
		if off < 0 || off >= len(reg) {
			return "?"
		}
		return reg[off]
	}
}

// fieldRegion names regions of a sep-delimited artifact by field index.
func fieldRegion(doc []byte, sep byte, names ...string) func(int) string {
	return func(off int) string {
		n := bytes.Count(doc[:min(off, len(doc))], []byte{sep})
		if n < len(names) {
			return names[n]
		}
		return fmt.Sprintf("field%d", n)
	}
}

type tgt = verifierflip.Target

// ---- the targets -----------------------------------------------------------

func manifestTarget(t testing.TB) tgt {
	key := fixedKey("manifest")
	m := backupfmt.Manifest{
		FormatVersion: 1, Backend: "sqlite",
		CreatedAt:   time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
		SchemaEpoch: 7,
		Tables: []backupfmt.TableEntry{
			{Name: "users", TarName: "tables/users.ndjson", RowCount: 3, UncompressedSize: 1234, SHA256: hex.EncodeToString(fixedKey("t1")), Columns: []string{"id", "name"}},
			{Name: "secret_nodes", TarName: "tables/secret_nodes.ndjson", RowCount: 9, UncompressedSize: 99, SHA256: hex.EncodeToString(fixedKey("t2")), Columns: []string{"id"}},
		},
		KeyFiles: []backupfmt.KeyFileEntry{{OriginalPath: "dek.key", TarName: "keys/dek.key", Mode: 0o600, SHA256: hex.EncodeToString(fixedKey("k1")), Size: 60}},
	}
	if err := backupfmt.SignManifest(&m, key); err != nil {
		t.Fatal(err)
	}
	art, _ := json.Marshal(m)
	return tgt{
		Name: "backup-manifest-hmac", Artifact: art,
		Verify: func(b []byte) bool {
			var x backupfmt.Manifest
			return json.Unmarshal(b, &x) == nil && backupfmt.VerifyManifestSignature(x, key)
		},
		Canon: func(b []byte) string {
			var x backupfmt.Manifest
			_ = json.Unmarshal(b, &x)
			o, _ := json.Marshal(x)
			return string(o)
		},
		Region: jsonRegion(art),
	}
}

func highWaterTargets(t testing.TB) []tgt {
	key := fixedKey("checkpoint")
	mk := func(name string, cp *auditverify.Checkpoint) tgt {
		sig := auditverify.SignCheckpoint(cp, key)
		art := []byte(auditverify.EncodeHighWater(cp, sig))
		return tgt{
			Name: name, Artifact: art,
			Verify: func(b []byte) bool {
				c, s, ok := auditverify.ParseHighWater(string(b))
				return ok && auditverify.HighWaterSigMatches(c, s, key)
			},
			Canon: func(b []byte) string {
				c, s, _ := auditverify.ParseHighWater(string(b))
				return auditverify.EncodeHighWater(c, s)
			},
			MACStart: len(art) - 64, MACEnd: len(art),
			Seps:   [][]byte{{0x1f}},
			Region: fieldRegion(art, 0x1f, "version", "f1", "f2", "f3", "f4", "f5", "f6", "sig"),
		}
	}
	h := hex.EncodeToString(fixedKey("head"))
	return []tgt{
		mk("audit-highwater-v1", &auditverify.Checkpoint{ChainedEvents: 1234, HeadID: 1300, HeadHash: h, KeyVersion: "kek-1"}),
		mk("audit-highwater-v2-sealed", &auditverify.Checkpoint{ChainedEvents: 1234, HeadID: 1300, HeadHash: h, KeyVersion: "kek-1", Seals: 2, SealDigest: hex.EncodeToString(fixedKey("seal"))}),
	}
}

func anchorBundleTargets(t testing.TB) []tgt {
	key := fixedKey("checkpoint")
	cp := &auditverify.Checkpoint{ChainedEvents: 55, HeadID: 60, HeadHash: hex.EncodeToString(fixedKey("head")), KeyVersion: "kek-1"}
	cp.Signature = auditverify.SignCheckpoint(cp, key)
	b := auditverify.ExternalAnchorBundle{ChainedEvents: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion, Signature: cp.Signature, AnchorToken: []byte("rfc3161-token-bytes"), AnchorProvider: "tsa.example"}
	art, _ := json.Marshal(b)
	verify := func(d []byte) bool {
		x, err := auditverify.ParseExternalAnchorBundle(d)
		if err != nil {
			return false
		}
		return auditverify.CheckpointSignatureValid(&auditverify.Checkpoint{ChainedEvents: x.ChainedEvents, HeadID: x.HeadID, HeadHash: x.HeadHash, KeyVersion: x.KeyVersion, Signature: x.Signature}, key)
	}
	signed := tgt{
		Name: "audit-external-anchor-bundle", Artifact: art, Verify: verify,
		// Canon = the signature-covered fields. anchor_token/anchor_provider are
		// not covered by the checkpoint signature by design (the RFC3161 token is
		// authenticated by internal/notary elsewhere); the sibling target below
		// makes that visible.
		Canon: func(d []byte) string {
			x, _ := auditverify.ParseExternalAnchorBundle(d)
			return fmt.Sprintf("%d|%d|%s|%s|%s", x.ChainedEvents, x.HeadID, x.HeadHash, x.KeyVersion, x.Signature)
		},
		Region: jsonRegion(art),
	}
	full := tgt{
		Name: "audit-external-anchor-bundle-unsigned-fields-informational", Artifact: art, Verify: verify,
		Canon: func(d []byte) string {
			x, _ := auditverify.ParseExternalAnchorBundle(d)
			o, _ := json.Marshal(x)
			return string(o)
		},
		Region: jsonRegion(art),
	}
	return []tgt{signed, full}
}

func sealTarget(t testing.TB) tgt {
	key := fixedKey("checkpoint")
	var lines []string
	prev := ""
	for i := 1; i <= 2; i++ {
		s := auditverify.Seal{V: 1, Seq: i, Prev: prev, At: time.Date(2026, 11, 6, 12, i, 0, 0, time.UTC), Operator: "op", OSUser: "root", Reason: "disk loss", Evidence: "ticket-1",
			Gaps:  []auditverify.SealGap{{LastGoodID: uint64(10 * i), LastGoodHash: "aa", ResumeID: uint64(10*i + 5), ResumeHash: "bb"}},
			After: auditverify.SealCount{Events: 40, HeadID: 50, HeadHash: "cc"}, LostEvents: 4}
		payload, _ := json.Marshal(&s)
		sum := sha256.Sum256(payload)
		prev = hex.EncodeToString(sum[:])
		kid := "kek-1"
		lines = append(lines, strings.Join([]string{"aseal-v1", base64.RawURLEncoding.EncodeToString(payload), kid, hmacHex(key, []byte("auditseal-v1\x00"+kid+"\x00"), payload)}, "\x1f"))
	}
	art := []byte(strings.Join(lines, "\n"))
	return tgt{
		Name: "audit-seal-records", Artifact: art,
		Verify: func(b []byte) bool {
			recs, err := auditverify.ParseSeals(string(b))
			if err != nil || len(recs) != 2 {
				return false
			}
			for _, r := range recs {
				if !r.MACValid(key) {
					return false
				}
			}
			return true
		},
		Canon: func(b []byte) string {
			recs, _ := auditverify.ParseSeals(string(b))
			var sb strings.Builder
			for _, r := range recs {
				fmt.Fprintf(&sb, "%s|%s;", r.Digest(), r.KeyVersion())
			}
			// The MAC string itself is part of the meaning; recover it from
			// the raw line since Seal does not export it.
			for ln := range strings.SplitSeq(string(b), "\n") {
				p := strings.Split(ln, "\x1f")
				if len(p) == 4 {
					sb.WriteString(p[3] + ";")
				}
			}
			return sb.String()
		},
		Seps: [][]byte{{0x1f}, {'\n'}},
		Region: func(off int) string {
			return fmt.Sprintf("line%d/%s", bytes.Count(art[:off], []byte{'\n'}), fieldRegion(art, 0x1f, "tag", "payload", "kid", "mac")(off))
		},
	}
}

func keyTransitionTarget(t testing.TB) tgt {
	keys := [][]byte{fixedKey("kt0"), fixedKey("kt1"), fixedKey("kt2")}
	var lines []string
	prev := ""
	for i := 1; i <= 2; i++ {
		k := auditverify.KeyTransition{V: 1, Seq: i, OldKID: fmt.Sprintf("kek-%d", i-1), NewKID: fmt.Sprintf("kek-%d", i), HeadID: uint64(100 * i), HeadHash: "hh", CheckpointID: uint64(i), Checkpoint: "cp", State: "st", Prev: prev}
		payload, _ := json.Marshal(&k)
		sum := sha256.Sum256(payload)
		prev = hex.EncodeToString(sum[:])
		dom := "auditkeytrans-v1\x00"
		macOld := hmacHex(keys[i-1], []byte(dom+"old\x00"), payload)
		macNew := hmacHex(keys[i], []byte(dom+"new\x00"), payload, []byte("\x00"+macOld))
		lines = append(lines, strings.Join([]string{"akt-v1", base64.RawURLEncoding.EncodeToString(payload), macOld, macNew}, "\x1f"))
	}
	art := []byte(strings.Join(lines, "\n"))
	return tgt{
		Name: "audit-key-transitions", Artifact: art,
		Verify: func(b []byte) bool {
			recs, err := auditverify.ParseKeyTransitions(string(b))
			if err != nil || len(recs) != 2 {
				return false
			}
			for i, r := range recs {
				if !r.OldMACValid(keys[i]) || !r.NewMACValid(keys[i+1]) {
					return false
				}
			}
			return true
		},
		Canon: func(b []byte) string {
			recs, _ := auditverify.ParseKeyTransitions(string(b))
			var sb strings.Builder
			for _, r := range recs {
				sb.WriteString(r.Digest() + ";")
			}
			for ln := range strings.SplitSeq(string(b), "\n") {
				p := strings.Split(ln, "\x1f")
				if len(p) == 4 {
					sb.WriteString(p[2] + "|" + p[3] + ";")
				}
			}
			return sb.String()
		},
		Seps: [][]byte{{0x1f}, {'\n'}},
		Region: func(off int) string {
			return fmt.Sprintf("line%d/%s", bytes.Count(art[:off], []byte{'\n'}), fieldRegion(art, 0x1f, "tag", "payload", "macOld", "macNew")(off))
		},
	}
}

func retentionTargets(t testing.TB) []tgt {
	key := fixedKey("checkpoint")
	pH, eH := hex.EncodeToString(fixedKey("p")), hex.EncodeToString(fixedKey("e"))
	v1 := strings.Join([]string{"v1", "42", pH, eH, "kek-1", auditverify.SignRetentionAnchor(42, pH, eH, "kek-1", key)}, "\x1f")
	v2 := strings.Join([]string{"v2", "42", pH, eH, "17", "kek-1", auditverify.SignRetentionAnchorV2(42, pH, eH, 17, "kek-1", key)}, "\x1f")
	mk := func(name, art string) tgt {
		a := []byte(art)
		return tgt{
			Name: name, Artifact: a,
			Verify: func(b []byte) bool {
				x, ok := auditverify.ParseRetentionAnchorValue(string(b))
				return ok && x.SigMatches(key)
			},
			Canon: func(b []byte) string {
				x, _ := auditverify.ParseRetentionAnchorValue(string(b))
				return fmt.Sprintf("%+v", x)
			},
			MACStart: len(a) - 64, MACEnd: len(a),
			Seps:   [][]byte{{0x1f}},
			Region: fieldRegion(a, 0x1f, "layout", "row_id", "prev", "entry", "f4", "f5", "sig"),
		}
	}
	return []tgt{mk("audit-retention-anchor-v1", v1), mk("audit-retention-anchor-v2", v2)}
}

func aeadTargets(t testing.TB) []tgt {
	svc, err := aead.NewEncryptionService(fixedKey("kek"))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("secret:42:v3")
	ed, err := svc.EncryptWithAAD([]byte("hunter2-plaintext-value"), "kek-1", aad)
	if err != nil {
		t.Fatal(err)
	}
	ed.Metadata.EncryptedAt = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	art, _ := aead.SerializeEncryptedData(ed)
	verify := func(b []byte) bool {
		d, err := aead.DeserializeEncryptedData(b)
		if err != nil {
			return false
		}
		_, err = svc.DecryptWithAAD(d, aad)
		return err == nil
	}
	plain := func(b []byte) string {
		d, _ := aead.DeserializeEncryptedData(b)
		p, _ := svc.DecryptWithAAD(d, aad)
		return string(p)
	}
	main := tgt{Name: "aead-envelope-plaintext", Artifact: art, Verify: verify, Canon: plain, Region: jsonRegion(art)}
	// Metadata variant: KeyVersion/EncryptedAt/AADVersion are not covered by
	// the GCM tag; this target makes that visible instead of hiding it.
	meta := tgt{Name: "aead-envelope-metadata-informational", Artifact: art, Verify: verify,
		Canon: func(b []byte) string {
			d, _ := aead.DeserializeEncryptedData(b)
			return plain(b) + fmt.Sprintf("|%+v", d.Metadata)
		}, Region: jsonRegion(art)}

	chunks, err := svc.EncryptChunked(bytes.Repeat([]byte("0123456789abcdef"), 6), 32, "kek-1")
	if err != nil {
		t.Fatal(err)
	}
	cart, _ := json.Marshal(chunks)
	chunked := tgt{Name: "aead-chunked-stream", Artifact: cart,
		Verify: func(b []byte) bool {
			var cs []*aead.EncryptedData
			if json.Unmarshal(b, &cs) != nil {
				return false
			}
			_, err := svc.DecryptChunked(cs)
			return err == nil
		},
		Canon: func(b []byte) string {
			var cs []*aead.EncryptedData
			_ = json.Unmarshal(b, &cs)
			p, _ := svc.DecryptChunked(cs)
			return string(p)
		},
		Region: jsonRegion(cart),
	}
	return []tgt{main, meta, chunked}
}

func pqwrapTargets(t testing.TB) []tgt {
	var out []tgt
	for _, s := range []pqwrap.Suite{pqwrap.SuiteX25519MLKEM768, pqwrap.SuiteX25519MLKEM1024} {
		seed, err := pqwrap.DeriveSeed(fixedKey("kek"), s, "epoch-1")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := pqwrap.NewPrivateKeyFromSeed(s, seed)
		if err != nil {
			t.Fatal(err)
		}
		ctx := []byte("dek:epoch-1")
		env, err := pqwrap.Wrap(priv.PublicKey(), pqwrap.PurposeDEK, ctx, fixedKey("dek"))
		if err != nil {
			t.Fatal(err)
		}
		ctLen := 1088
		if s == pqwrap.SuiteX25519MLKEM1024 {
			ctLen = 1568
		}
		out = append(out, tgt{
			Name: "pqwrap-envelope-" + s.String(), Artifact: env,
			Verify: func(b []byte) bool {
				_, err := pqwrap.Unwrap(priv, pqwrap.PurposeDEK, ctx, b)
				return err == nil
			},
			Canon: func(b []byte) string {
				k, _ := pqwrap.Unwrap(priv, pqwrap.PurposeDEK, ctx, b)
				return hex.EncodeToString(k)
			},
			Region: func(off int) string {
				switch {
				case off < 4:
					return "magic"
				case off < 8:
					return "version/suite/purpose"
				case off < 24:
					return "key_id"
				case off < 56:
					return "x25519"
				case off < 56+ctLen:
					return "mlkem_ct"
				default:
					return "sealed"
				}
			},
		})
		if s != pqwrap.SuiteX25519MLKEM1024 {
			continue
		}
		// keyset (recipients must be the 1024 suite)
		dek := fixedKey("keyset-dek")
		var kid [pqwrap.KEKIDSize]byte
		copy(kid[:], "kekid-0123456789")
		ks, err := pqwrap.SealKeyset(dek, fixedKey("kek"), kid, []*pqwrap.PublicKey{priv.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tgt{
			Name: "pqwrap-keyset-mac", Artifact: ks,
			Verify: func(b []byte) bool { _, err := pqwrap.OpenKeyset(b, fixedKey("kek")); return err == nil },
			Canon: func(b []byte) string {
				k, _ := pqwrap.OpenKeyset(b, fixedKey("kek"))
				var sb strings.Builder
				sb.WriteString(hex.EncodeToString(k.DEK) + hex.EncodeToString(k.KEKID[:]))
				for _, r := range k.Recipients {
					sb.WriteString(hex.EncodeToString(r.Bytes()))
				}
				return sb.String()
			},
			MACStart: len(ks) - 32, MACEnd: len(ks),
		})
		leg, err := pqwrap.SealLegacy(dek, fixedKey("kek"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tgt{
			Name: "pqwrap-legacy60-keyfile", Artifact: leg,
			Verify: func(b []byte) bool { _, _, err := pqwrap.OpenKeyFile(b, fixedKey("kek")); return err == nil },
			Canon: func(b []byte) string {
				k, _, _ := pqwrap.OpenKeyFile(b, fixedKey("kek"))
				return hex.EncodeToString(k.DEK)
			},
		})
	}
	return out
}

func recoveryKeyTargets(t testing.TB) []tgt {
	raw, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	stored := recoverykey.Hash(raw)
	return []tgt{
		{Name: "recoverykey-entered-key", Artifact: []byte(raw),
			Verify: func(b []byte) bool { return recoverykey.Verify(string(b), stored) },
			Canon:  func(b []byte) string { return recoverykey.Normalize(string(b)) }},
		{Name: "recoverykey-stored-hash", Artifact: []byte(stored),
			Verify:   func(b []byte) bool { return recoverykey.Verify(raw, string(b)) },
			MACStart: 0, MACEnd: len(stored)},
	}
}

func evidenceTarget(t testing.TB) tgt {
	c := core.NewKeyorixCore(nil)
	key := fixedKey("evidence")
	c.SetEvidenceSignKey(key, "kek-1")
	const filename = "evidence-pack-2026-11.zip"
	data := []byte("PK-evidence-pack-bytes-0123456789")
	mac := hmacHex(key, []byte(filename), []byte{0}, data)
	art := append([]byte("kek-1:"+mac+"\n"), data...)
	split := func(b []byte) (sig string, d []byte, ok bool) {
		before, after, ok := bytes.Cut(b, []byte{'\n'})
		if !ok {
			return "", nil, false
		}
		return string(before), after, true
	}
	return tgt{
		Name: "evidence-pack-signature", Artifact: art,
		Verify: func(b []byte) bool {
			sig, d, ok := split(b)
			return ok && c.VerifyEvidenceSignature(filename, d, sig).Valid
		},
		Canon: func(b []byte) string {
			sig, d, _ := split(b)
			v, h, _ := strings.Cut(sig, ":")
			raw, _ := hex.DecodeString(h)
			return v + "|" + hex.EncodeToString(raw) + "|" + string(d)
		},
		Region: func(off int) string {
			if off < 6 {
				return "version"
			}
			if off < 6+64 {
				return "mac"
			}
			return "data"
		},
		MACStart: 6, MACEnd: 70,
	}
}

func licenseTarget(t testing.TB) tgt {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	reg := trust.NewRegistry()
	if err := reg.Add(trust.PurposeLicense, "lic-1", pub); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	tok, err := licenseverify.Issue(licenseverify.License{Licensee: "Acme", Plan: "enterprise", Features: []string{"airgap_updates", "billing"},
		IssuedAt: now.Add(-24 * time.Hour), NotAfter: now.Add(400 * 24 * time.Hour), MaxSeats: 50, KeyID: "lic-1"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	eval := func(b []byte) licenseverify.Status {
		return licenseverify.Evaluate(string(b), reg, "", now, time.Hour)
	}
	return tgt{
		Name: "license-ed25519-token", Artifact: []byte(tok),
		Verify: func(b []byte) bool { return eval(b).State == licenseverify.StateActive },
		Canon: func(b []byte) string {
			s := strings.TrimSpace(string(b))
			p, sg, _ := strings.Cut(s, ".")
			pd, _ := base64.RawURLEncoding.DecodeString(p)
			sd, _ := base64.RawURLEncoding.DecodeString(sg)
			return string(pd) + "|" + hex.EncodeToString(sd)
		},
		Seps: [][]byte{{'.'}},
		Region: func(off int) string {
			if off <= strings.IndexByte(tok, '.') {
				return "payload"
			}
			return "signature"
		},
		MACStart: strings.IndexByte(tok, '.') + 1, MACEnd: len(tok),
	}
}

// ---- the tests ---------------------------------------------------------------

func allTargets(t testing.TB) []tgt {
	var ts []tgt
	ts = append(ts, manifestTarget(t))
	ts = append(ts, highWaterTargets(t)...)
	ts = append(ts, anchorBundleTargets(t)...)
	ts = append(ts, sealTarget(t), keyTransitionTarget(t))
	ts = append(ts, retentionTargets(t)...)
	ts = append(ts, aeadTargets(t)...)
	ts = append(ts, pqwrapTargets(t)...)
	ts = append(ts, recoveryKeyTargets(t)...)
	ts = append(ts, evidenceTarget(t), licenseTarget(t))
	ts = append(ts, extraTargets(t)...)
	return ts
}
