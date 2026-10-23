# Demo: TPM-sealed KEK, PCR mismatch and recovery (5 minutes)

> **NOT IMPLEMENTED.** This script is written against the CLI that
> [ADR-116](../adr-116-tpm-sealed-kek-pcr-policy-recovery.md) proposes (status: Proposed). The
> `admin encryption tpm …` commands, the `key_provider.tpm` config block and the messages below
> do not exist on main yet. Running it today fails at step 1. Tool flags marked [VERIFY] were not
> run in this session. Lab validation is **pending the e2e VM**.

**Audience:** assessor, accelerator or investor. **Shows:** a stolen data dir is useless on
another machine; the genuine machine starts unattended; a changed boot state is refused loudly;
the recovery code brings the same key back, and the use is audited.

**Setup (before the clock starts):** a Linux VM, `swtpm` and `tpm2-tools` installed [VERIFY
package names], the `tpm_vtpm_proxy` module loaded, and two software TPMs ("host A" and
"host B") exposed as devices:

```bash
mkdir -p /tmp/demo/tpmA /tmp/demo/tpmB
swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir=/tmp/demo/tpmA &   # prints /dev/tpmN  [VERIFY]
swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir=/tmp/demo/tpmB &   # second TPM  [VERIFY]
export TPM_A=/dev/tpmrm1 TPM_B=/dev/tpmrm2      # as printed; resource-managed nodes
```

`demo.yaml` (only the encryption part shown):

```yaml
storage:
  encryption:
    enabled: true
    key_provider:
      type: tpm
      tpm_device: /dev/tpmrm1
      wrapped_key_path: keys/kek.tpm
      tpm:
        pcr_policy: secure-boot
        allow_secure_boot_off: true   # swtpm has no firmware; demo only, never in production
```

## 0:00 – Seal the KEK to host A (60 s)

```bash
keyorix-server admin encryption tpm init --config demo.yaml
```

Expected: device and manufacturer, "Secure Boot: off (allowed by config: demo only)", PCR 7
value, "sealing a new KEK to this TPM with policy PCR 7 (sha256)…", then the **recovery code**,
shown once in 13 groups of 4 characters, and a prompt to type it back. Say: *"This code is the
only way back if this machine's boot state or TPM changes. It is shown once, never stored on the
host and never logged."*

```bash
keyorix-server admin encryption tpm status --config demo.yaml
```

Shows: sealed PCR 7 equals current PCR 7, policy digest matches, recovery slot present.

## 1:00 – Normal start, write and read a secret (45 s)

```bash
keyorix-server --config demo.yaml &          # starts with no passphrase prompt
printf 'hunter2-demo' | keyorix secret create --name db-password --from-file -
keyorix secret get --name db-password --show-value
```

Say: *"No passphrase at boot. The KEK only exists inside this TPM and in memory."*

## 1:45 – Stolen data dir on host B (45 s)

```bash
cp -a "$PWD" /tmp/demo/hostB            # config, database and key files: the whole install
cd /tmp/demo/hostB
sed -i 's#/dev/tpmrm1#/dev/tpmrm2#' demo.yaml   # host B's own TPM
keyorix-server --config demo.yaml
cd -
```

Expected refusal (exit non-zero):
`SECURITY: tpm key provider: not-this-tpm: this blob was not sealed by this TPM, or the TPM was
cleared or reset … use the recovery code: keyorix-server admin encryption tpm recover`.
Say: *"Disk, database, key files: all copied. Nothing opens without host A's TPM."*

## 2:30 – Boot state changes on host A (45 s)

Stop the server and simulate a Secure Boot database update by extending PCR 7:

```bash
kill %1
TPM2TOOLS_TCTI=device:/dev/tpmrm1 tpm2_pcrextend 7:sha256=$(printf dbx-update | sha256sum | cut -d' ' -f1)   # [VERIFY]
keyorix-server --config demo.yaml
```

Expected refusal:
`SECURITY: tpm key provider: boot-state-changed: PCR 7 is 9f2c…, was 3a71… at seal time (Secure
Boot state or db/dbx changed). If you expected this, run: keyorix-server admin encryption tpm
recover`. Say: *"Same machine, same disk, different boot state. It refuses and says why."*

## 3:15 – Recover with the code (60 s)

```bash
keyorix-server admin encryption tpm recover --config demo.yaml
```

Expected: prompt for the code; "recovery slot opened; key check value matches; trial unwrap of
dek.key OK; resealing the same KEK to the current PCR 7…; audit event
encryption.tpm_recovery_used written; ROTATE THE RECOVERY CODE NOW". Then:

```bash
keyorix-server --config demo.yaml &
keyorix secret get --name db-password --show-value   # hunter2-demo
keyorix audit logs --event-type encryption.tpm_recovery_used
```

Say: *"The same key came back, so the audit chain and its checkpoints still verify. No key
rotation was needed, and the recovery itself is on the record."*

## 4:15 – Close the loop (45 s)

```bash
keyorix-server admin encryption tpm status --config demo.yaml    # posture: recovery used, code not rotated
keyorix-server admin encryption tpm recovery-code rotate --config demo.yaml
keyorix-server admin encryption tpm status --config demo.yaml    # warning cleared
```

Close with the limits, said out loud: *"This protects a copied disk, image or backup. It does
not protect against someone who is already root on the running machine. That needs attestation,
which is the next step."*

**Clean-up:** stop both `swtpm` processes and remove `/tmp/demo`.
