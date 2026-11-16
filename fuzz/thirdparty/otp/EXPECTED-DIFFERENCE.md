# EXPECTED-DIFFERENCE table — pquerna/otp base32 secret decoding vs strict RFC 4648

`FuzzOTPBase32Secret` compares pquerna's secret acceptance (`hotp.GenerateCodeCustom`
returns no error ⟺ the secret decoded) against a strict, CANONICAL RFC 4648 base32
reference (`strictBase32OK`): length a multiple of 8, alphabet `A-Z`/`2-7` in the body,
and `=` padding only as a trailing run of a valid count (0,1,3,4,6).

pquerna normalises a secret before decoding — `TrimSpace`, pad-to-%8 with `=`, `ToUpper`,
then `base32.StdEncoding.DecodeString` — so it ACCEPTS a strict superset. Every extra
acceptance must be one of the classes below (the fuzzer fails on an acceptance it cannot
explain with `{trim, pad, upper}`, and on any case where strict accepts but pquerna
rejects).

| Class | pquerna | strict RFC 4648 | Why expected / Keyorix impact |
|---|---|---|---|
| `lowercase` | accepts (`ToUpper`) | rejects | base32 alphabet is upper-case; pquerna upper-cases first. **Keyorix impact: none** — Keyorix stores the library-generated upper-case secret; it never feeds a lowercase secret. |
| `surrounding-whitespace` | accepts (`TrimSpace`) | rejects | leading/trailing spaces/newlines are trimmed. **Impact: none** — Keyorix secrets are generated, not pasted. |
| `missing-padding` | accepts (re-pads to %8) | rejects (requires canonical `=`) | a secret whose length is not a multiple of 8 is padded with `=`. **Impact: none** — Keyorix passes the full `key.Secret()`. |

## Upstream quirk NOT a finding (documented, not a class the oracle fails on)

Go's stdlib base32 decoder silently **skips `\r`/`\n`** and tolerates some **non-canonical
`=` placements**. During harness bring-up, using the stdlib decoder as "strict" made it
accept secrets (`"22222\n222"`, `"22222===2"`) that pquerna's length-based re-padding then
rejected — i.e. pquerna is the STRICTER of the two there (fail-safe: it rejects more). That
is an upstream stdlib-vs-pquerna quirk, benign for Keyorix (secrets are canonical,
library-generated, never attacker-controlled). The reference decoder was tightened to be
genuinely canonical so these no longer appear as differences; recorded here as ARTIFACT, not
a finding. Reproducers live in `testdata/fuzz/FuzzOTPBase32Secret/`.

## otpauth:// URL round-trip (`FuzzOTPURLRoundTrip`)

No EXPECTED-DIFFERENCE classes: the oracle requires exact idempotence of
`NewKeyFromURL → URL() → NewKeyFromURL` on `secret`/`type`/`algorithm`/`digits`/`period`.
Any drift is a finding, not an expected difference. None found.
