### Documentation
- **ADR-117 Amendment A (Proposed): prefer a signed PCR policy over raw PCR binding.** Design only, no behaviour change. It ranks a UKI PCR 11 signed policy (`signed-uki`) and systemd-pcrlock (`pcrlock`) above raw PCR 7, and compares them with raw PCR 0/2/4/7 on updates, rollback, dual-boot, Secure Boot db/dbx changes and root on the host. It also defines the planned-update and unplanned-refusal procedures, Shamir custody of the recovery code, and fail-closed rules. It states that Keyorix never claims to detect a compromised OS, and adds a claims-vs-evidence table. New: `docs/design/tpm-signed-pcr-policy.md`.
- **Resolved (review, Andrei 2026-10-28): `signed-uki` also requires Secure Boot on, TPM-enforced
  (binds PCR 7 alongside the PolicyAuthorize term over PCR 11).** Closes an offline-attacker path:
  with Secure Boot off, systemd-stub accepts a kernel command-line override (measured into PCR 12,
  not PCR 11), so the genuine, same-authority UKI could otherwise be booted into a debug shell and
  still unseal. A host with a signed UKI but Secure Boot off falls through to `pcrlock` or
  `secure-boot` (D10.5). Corrects the offline-attacker and Secure-Boot-db/dbx table rows, the
  same-authority risk row, and TPMK-P8 in the threat model to match; fixes the stale `[VERIFY]`
  marks on PCR 0/4/7/9/11 and the "Item 4" cross-reference; and states that the D10.5 chain is
  evaluated once, at `init` (`reseal`/`recover` use the recorded mode, never re-detecting it).
