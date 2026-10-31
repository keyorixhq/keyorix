# Host integrity posture (advisory, self-reported)

`keyorix admin validate --posture` prints a block of `integrity/...` lines that
answer "is this host's boot and binary integrity visible?". Every one of them is
labelled **advisory (self-reported)**, and so is the tier derived from them.

## Why a self-check is not proof

The server reads these facts from the host it runs on. A host that is
compromised below the server (a replaced kernel, a patched `/sys`, a modified
binary) can make every line say `ok`. The lines tell an operator what the host
reports; they do not convince anyone else. Proof needs a verifier outside the
host that checks a hardware-signed quote: TPM remote attestation
([ADR-117](../adr-117-tpm-sealed-kek-pcr-policy-recovery.md),
[ADR-119](../adr-119-attestation-gated-secret-release.md), and the
[TPM-sealed KEK threat model](threat-models/tpm-sealed-kek.md)).

These lines are informational. They are not deviations from the ADR-112 secure
baseline, are not counted toward the exit code, and are not read by `/health`,
startup or any refusal. An unreadable source is `unknown`, never `ok`.

## The lines

| Line | Reads | `ok` | `degraded` | `unknown` |
|---|---|---|---|---|
| `integrity/secure-boot` | `/sys/firmware/efi/efivars/SecureBoot-…` | firmware reports Secure Boot on | firmware reports it off | no EFI variable visible (legacy BIOS, container), unreadable, malformed |
| `integrity/kernel-lockdown` | `/sys/kernel/security/lockdown` | mode `integrity` or `confidentiality` | mode `none` | file absent, unreadable, unparseable |
| `integrity/ima` | `/sys/kernel/security/ima/policy` (root-only) | policy has an `appraise` rule | only `measure` rules, or empty | file absent or unreadable |
| `integrity/fs-verity` | `FS_IOC_GETFLAGS` on the running binary | fs-verity flag set | flag clear | ioctl failed (filesystem without the interface) |
| `integrity/release-manifest` | `checksums.txt` next to the binary | never plain `ok`: a listed SHA-256 prints `ok (signature not verified)` | hash not listed | manifest unreadable |
| `integrity/tpm-sealing` | `key_provider.type` and the sealed blob | provider is `tpm` and the blob exists | provider is not `tpm`, or no blob yet | blob unreadable |
| `integrity/keylime-agent` | `/proc/*/comm` | a `keylime_agent` process exists (presence only) | none found | `/proc` unreadable |

Notes:

- `release-manifest` is `not checked` when no manifest is shipped next to the
  binary, or when it has no signature file next to it. Nothing is fetched. The
  signature is not verified by the server (a signature file of any content,
  even an empty one, only unlocks the comparison), so a match prints
  `ok (signature not verified)` and does **not** count toward the tier. Run
  `scripts/release/verify-release.sh` for the real check.
- `ima` `ok` means a policy with appraise rules is loaded. Whether it is
  enforcing depends on the `ima_appraise=` boot mode, which this check does not read.
- `tpm-sealing` reads configuration and a file's existence. It does not talk to
  the TPM. The seal binds the KEK to the chip, not to a verified boot state.
- `keylime-agent` is presence of a process. It does not say whether a Keylime
  verifier currently accepts the host.
- On macOS and Windows the Linux-only lines print `not applicable`.

## Detected integrity tier (0 to 6)

The tier counts consecutive rungs from the top of the table; the first rung that
is not plain `ok` stops the count. `degraded`, `unknown`, `not checked` and a
qualified `ok (...)` all stop it.

| Tier | Rung reached (all rungs above it also hold) |
|---|---|
| 1 | Secure Boot enabled |
| 2 | kernel lockdown integrity or confidentiality |
| 3 | running binary identity (fs-verity enabled) |
| 4 | IMA appraise policy loaded |
| 5 | KEK sealed to a TPM |
| 6 | Keylime agent present |

Tier 0 means Secure Boot is not reported `ok`. The tier line also names the rung
that stopped the climb.

## How an immutable-OS / IMA deployment moves the tier

An image-based OS with a signed boot chain (Secure Boot on, kernel lockdown set
by the distribution) reaches tier 2 with no Keyorix configuration. Serving the
binary from a verity-protected filesystem, or enabling fs-verity on it, adds
tier 3. Loading an IMA policy with `appraise` rules (the measured-boot image
ships one) adds tier 4. Setting `storage.encryption.key_provider.type: tpm`
adds tier 5, and running a Keylime agent tier 6. The tier is a label for what
the host reports; moving up it does not make the report evidence. For evidence,
use TPM attestation as above.
