# Demo: agent tokens that can only narrow (5 minutes) — NOT IMPLEMENTED

> **Status: not implemented.** This script is written against the CLI that
> [ADR-116](../adr-116-attenuating-agent-tokens.md) (Proposed) describes. None of the
> `keyorix aat …` commands, the issuance endpoint or the `keyorix-mcp` holder mode exist
> yet. The expected outputs come from the RD-AAT-1 throwaway prototype (see
> [`design-rd-aat.md`](../design-rd-aat.md) section 5). They show the intended
> behaviour, not a recorded run of Keyorix.

What it shows: Keyorix issues one root token to an orchestrator agent. The orchestrator
derives a five-minute token for one secret without contacting Keyorix. A worker can use
it and nothing else. Every attempt to widen it is refused with a reason. Anyone holding
Keyorix's public key can verify the chain offline.

Needs (when implemented): a Keyorix server with the demo seed, a machine identity
`agent-orchestrator` with `secrets.read` on `payments/production` and `payments/staging`,
and the `keyorix` CLI.

## 0:00 – 0:30 The problem (talk)

- "Today an agent gets one machine token. Every sub-agent it hands work to gets the same
  token. A prompt injection anywhere in the chain can read everything that token can."
- "We want each hop to pass on less, without asking Keyorix every time, and we want
  that to be checkable."

## 0:30 – 1:15 Root token, issued once (run)

```
keyorix aat keygen --out orch.key                       # holder key for the orchestrator
keyorix aat issue --machine agent-orchestrator --holder-key orch.key \
  --tool secrets.read --ref payments/production/db-password \
  --ref payments/production/stripe-key --ref payments/staging/db-password \
  --ttl 15m --max-depth 2 --out root.aat
keyorix aat inspect root.aat
```

Expected: `depth 0/2, expires in 15m, tool …/tools/secrets.read ref one_of [3 refs]`.
Say: "Keyorix checked the request against this machine's RBAC for every possible name,
including secrets created later."

Then show a refusal:
`keyorix aat issue … --ref-glob 'payments/*/db-password'` is refused with
`ref pattern covers environments agent-orchestrator has no grant on (e.g. payments/A/db-password)`.

## 1:15 – 2:15 Derive offline, use it (run)

```
keyorix aat keygen --out worker.key
keyorix aat derive --parent root.aat --parent-key orch.key --holder-key worker.key \
  --tool secrets.read --ref payments/production/db-password --ttl 5m --terminal --out child.aat
KEYORIX_MCP_HOLDER_KEY=worker.key KEYORIX_MCP_CHAIN=root.aat,child.aat keyorix-mcp   # in the agent client
```

In the agent, ask for `payments/production/db-password`: the value comes back. Ask for
`payments/production/stripe-key`: the request is denied. The server log and audit show
`DENY step 6b argument "ref" = "payments/production/stripe-key" violates its constraint`.

Say: "`derive` made no network call. The worker's key never left `keyorix-mcp`, so the
model cannot copy it."

## 2:15 – 3:30 Try to widen it (run)

```
keyorix aat derive --parent root.aat --parent-key orch.key --holder-key worker.key \
  --tool secrets.read --ref payments/production/db-password --ref billing/production/stripe-key \
  --ttl 5m --out wide.aat
```

Expected (the deriver refuses):
`refused 4p4: tool …/secrets.read: argument "ref": one_of does not subsume one_of: values not a subset of the parent's`.

Force it (`--unchecked`, a demo-only flag that skips the deriver's check) and present
it: the server denies with the same step and reason. Then show the other dimensions:

| Attempt | Expected verdict |
|---|---|
| add a tool the root does not have | `DENY step 4p1 … adds tool … the parent does not authorize` |
| `--ttl 30m` under a 15-minute root | `DENY step 4h … outlives its parent` |
| the worker re-delegates its terminal token | `refused: parent is terminal` / `DENY step 4e` |
| another agent presents the worker's chain with its own key | `DENY step 7b pop signature does not verify under leaf cnf.jwk` |

## 3:30 – 4:15 Verify offline (run, network off)

```
keyorix aat export-trust-anchors --out keyorix-aat-keys.json     # once, online
# disconnect the network
keyorix aat verify --trust-anchors keyorix-aat-keys.json --chain root.aat,child.aat
keyorix aat verify --trust-anchors keyorix-aat-keys.json --chain root.aat,wide.aat
```

Expected: `chain valid: 2 tokens, leaf authorizes …/secrets.read ref = payments/production/db-password, expires in 4m`,
then `DENY step 4p4 …` for the widened chain. Say: "No Keyorix server took part. This
is what a third-party tool server would run."

## 4:15 – 5:00 Revoke and evidence (run)

```
keyorix aat revoke root.aat
```

In the agent, the same read is now denied: `root token revoked`. Say: "Offline verifiers
only see expiry, but Keyorix checks the root and the machine's live RBAC on every
request." Show `keyorix audit list --since 5m`: one intent and one outcome for the
permitted read, with the root id and the chain digests, and the denials with their
steps. (The ledger records depend on the RD-AGENT-LEDGER-1 ADR.)
