# Design note: TPM update and recovery procedures (ADR-117 Amendment A)

Status: **design only, nothing implemented.** The decisions are in
[ADR-117](../adr-117-tpm-sealed-kek-pcr-policy-recovery.md), Amendment A (D10 to D13), which is
Proposed. Session RD-TIER-ADR117-1, 2026-10-27, origin/main `6144d535f`. Source tags [S1] to [S5]
are defined in the ADR. The commands named here are the planned surface from
[design-rd-tpm-seal.md](../design-rd-tpm-seal.md) §6, and none of them exist yet.

## 1. Before any update that touches the boot chain

These updates touch the boot chain: firmware, Secure Boot variables (db, dbx, KEK, PK), the boot
loader, the kernel or UKI, and the TPM firmware.

1. Run `admin encryption tpm status`. It shows the mode, the sealed and current values, the
   predicted outcome of the next boot, and whether a recovery slot exists.
2. Confirm that the recovery code, or K of its N Shamir shares, can actually be reached by the
   person who will be at the console after the reboot. If it cannot, stop the update.
3. Per mode:

| Mode | Firmware | Secure Boot db/dbx | Boot loader or kernel |
|---|---|---|---|
| `signed-uki` | nothing | nothing | nothing, as long as the new UKI is signed with the same key. A new key means planning a recovery (§2) |
| `pcrlock` | host: `systemd-pcrlock unlock-firmware-code`, update, then `make-policy` ([S4]) | host: `unlock-firmware-config`, update, then `make-policy` ([S4]) | host: add the new kernel's `.pcrlock` variant, then `make-policy` ([S4]) |
| `secure-boot` | usually nothing ([S2]). `status` says if PCR 7 will move | **plan a recovery**: PCR 7 will change | usually nothing, while the same authority signs it [VERIFY] |
| `custom` with 0, 2 or 4 | plan a recovery | plan a recovery | plan a recovery |
| `none` | nothing (blob not bound). An fTPM reset still needs §2 | nothing | nothing |

4. Keyorix never unbinds the policy for the update window. Flatcar's "remove the PCR binding
   before updating" workaround ([S1]) is the unbound window that Decision 5 rejected. "Plan a
   recovery" therefore means: reboot, expect the refusal, run §2 with the code at hand.

## 2. When the server refuses to start

The refusal is a stderr line `SECURITY: tpm key provider: <class>: …` and a non-zero exit (ADR-117
D5, D6). There is no fallback.

| Class | First question | If explained | If not explained |
|---|---|---|---|
| `tpm-unavailable` | Is the device there, and is the service user in the tss group? | Fix access and restart. No recovery needed | Treat as host tampering: §2.1 |
| `boot-state-changed` | Does the PCR diff or the missing signature match a known update (§1)? | `admin encryption tpm recover` on this host | §2.1 |
| `not-this-tpm` | Board swap, TPM clear or fTPM reset by a firmware update? | `tpm recover` on this host. It reseals onto the new TPM | §2.1 |
| `blob-corrupt` / `blob-missing` | Was a file restored or edited? | Restore the blob from backup. If none exists, `tpm recover` | §2.1 |

`tpm recover` is an offline host command run as the service user (ADR-108). It reads the code
from the TTY, or the shares (§3), and checks `kek_id` and a trial unwrap of `dek.key` before
writing anything. It reseals **the same KEK** under the configured mode and writes
`encryption.tpm_recovery_used` with the class and the diff. It sets the sticky posture warning
until `recovery-code rotate` runs. A failure at any step leaves the files byte-identical (design
§5).

### 2.1 The diff is not explained

Do not recover on that host: a recovered KEK on a compromised host is a disclosed KEK. Instead:

1. Keep the host off the network. Preserve the TPM event log and the PCR values from `status` as
   evidence.
2. On known-good hardware: restore the data directory and run `tpm recover` there.
3. Then `recovery-code rotate`, an ADR-010 DEK sweep (D9: the old wraps cannot be revoked), and a
   rotation of every secret the old host could have read (incident runbook).

## 3. Offline recovery material

| Material | Wraps | Status |
|---|---|---|
| Recovery code (256-bit, 52 base32 characters) | the KEK | ADR-117 D3, planned PR A/B |
| Recovery code held as Shamir K-of-N shares | the same code | Amendment A D11.3, needs approval |
| PQWRAP hybrid escrow slot | the DEK | ADR-117 Decision 4, after #3662 option R ships |

- Shares are produced once, at `init` or at `recovery-code rotate`, with the split primitive in
  `internal/crypto/shamir.go`. They go to custodians and are never stored on the host. The code
  is wiped after splitting, as `encryption shamir-split` already does for a KEK.
- A Shamir payload carries no integrity of its own: with K-1 genuine shares a forged share can
  steer the result (#429, `shamir_provider.go`). The integrity check here is the recovery slot's
  AES-GCM tag plus `kek_id`, both outside the shares. A wrong recombination fails to open the
  slot, and nothing is written.
- Losing the code (or more than N-K shares) **and** the boot state means data loss, by design.
  `status` warns when no slot exists.

## 4. Fail-closed rules the implementation must keep

- No automatic downgrade: not from `signed-uki`, `pcrlock` or `secure-boot` to `none`, and not to
  another provider. The existing `AllowWeakerFallback` rules are unchanged (TPMK-7 in the threat
  model).
- A missing or unparsable UKI public key, signature JSON or pcrlock NV index is a refusal with a
  named file. It is never "seal or unseal without policy".
- `init` in a signed mode verifies once, before it reports success, that the current boot
  satisfies the policy it just created. The same rule exists for systemd-cryptenroll's
  `--tpm2-signature` ([S2]).
- The default-mode chain (ADR-117 D10.5) is evaluated once, at `init`. `reseal` and `recover` use
  the mode recorded in config/the blob, never re-detecting it; a missing input for that recorded
  mode at `reseal`/`recover` time is a refusal (the rule above), not a silent re-pick of a weaker
  mode.
- Recovery is never reachable over HTTP or gRPC, and never triggered by the server itself.

## 5. Lab prerequisites (pending e2e VM / hardware)

- One host that boots a systemd-stub UKI signed with a test PCR key (ukify), with the
  `ready`-phase signature present. It is needed for every `signed-uki` claim.
- One host with systemd 255 or later and an initialised `systemd-pcrlock` policy ([S4]).
- The existing D8 items: swtpm on the e2e VM, and a physical TPM 2.0 with Secure Boot on.
