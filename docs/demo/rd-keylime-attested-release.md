# Demo: a secret released only to an attested host (5 minutes)

**Status: NOT IMPLEMENTED. Pending e2e VM.** Written against the *future* CLI proposed in
[ADR-116](../adr-116-attestation-gated-secret-release.md); the command names below are
placeholders and do not exist. Lab environment: software TPM (swtpm) plus Keylime verifier,
registrar and agent. A software TPM shows the protocol, **not** hardware-rooted trust; say so out
loud during the demo.

Setup (done before the audience arrives, not part of the five minutes): lab steps 1 to 3 of
[`design-rd-keylime-spike.md`](../design-rd-keylime-spike.md) §8; one test secret
`demo/attested-token`; a machine identity bound to the agent UUID.

| Min | Step | Command (future CLI, not implemented) | What the audience sees |
|---|---|---|---|
| 0:00 | Frame | none | One sentence: a valid credential alone is not enough; the host's verified state must be good too |
| 0:30 | Policy | `keyorix project attestation set demo --verifier lab --max-age 60s` then `keyorix project attestation show demo` | Policy: verifier, allowed state 3, max age |
| 1:00 | Bind | `keyorix machine bind-agent demo-host --agent-uuid <uuid>` | Binding recorded, with an audit entry |
| 1:30 | Positive | on the host: `keyorix secret get demo/attested-token` | Value returned. Then `keyorix audit tail -n 1`: the record carries agent UUID, state 3, evidence age |
| 2:30 | Drift | on the host: `tpm2_pcrextend 16:sha256=<digest>` on the monitored PCR (lab step 5) | Within the verifier's polling interval its state leaves 3 |
| 3:15 | Refusal | same `secret get` again | **Denied**, no value, reason `attestation_failed`; audit shows the deny |
| 3:45 | Verifier down | on a second enrolled host still in state 3: stop the verifier container, run `secret get` | Denied with reason `verifier_unreachable`: fail closed, availability cost stated |
| 4:30 | Limits | none | Say: software TPM only; a pass proves the node, not the requester (ATT-2); physical TPM run is next |

Honest notes for the presenter:

- Rows 2:30 to 3:45 depend on lab observations (which state follows a PCR change, whether
  the verifier recovers by itself) that are `[VERIFY]` in the design note. If the lab shows
  different behaviour, the script and the design note are updated, not the narration.
- No timings are quoted in this repo. If the report records a detection delay, it stays in the
  report.
- The row at 3:45 needs rehearsal: after drift the host stays failed, so the verifier-down
  case is best shown on a second enrolled host that is still in state 3.
