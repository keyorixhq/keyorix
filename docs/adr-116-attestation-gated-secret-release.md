# ADR-116: Attestation-gated secret release (Keyorix as RATS relying party)

**Status:** Proposed (2026-10-23). Not accepted until Andrei approves; no code follows before then.
**Date:** 2026-10-23
**Context:** RD-KEYLIME-SPIKE-1. Full reasoning, sources and the build-vs-adopt table:
[`design-rd-keylime-spike.md`](design-rd-keylime-spike.md). Source tags (`[KL-docs]`, `[VERIFY]`,
...) are defined there; this ADR repeats only what the decisions rest on.

## Non-negotiable invariants this ADR must not weaken

- **Audit-before-disclosure** (see ADR-115): no secret value is returned before its audit record
  is durable. The attestation verdict is part of that record.
- **Authorization is not widened.** `core.Authorize` stays the only place that grants access.
- **Fail closed.** No weaker-fallback switch (compare KEY-2 in the key-hierarchy threat model).

## Context

A valid credential is enough today to read a secret, whatever state the requesting host is in.
Remote attestation (RFC 9334) lets a Verifier appraise a host's TPM-backed evidence and a
Relying Party act on the result. Keylime is an Apache-2.0 verifier/agent/registrar stack that
polls enrolled hosts and exposes per-agent state over mTLS REST; the documented response carries
an `operational_state`, no signature and no documented timestamp (design §3.3).

## Decisions

**D1. Adopt Keylime as the Verifier; build only a relying-party adapter and gate (hybrid).**
Justification: the parts we would otherwise build (enrolment with EK/AK binding, a polling
state machine, a boot-log policy engine) are the bulk of the work and already exist; the gate is
the only Keyorix-specific part (design §6).

**D2. The gate is deny-only, runs after `core.Authorize`, and can only turn allow into deny.**
Justification: a gate bug can over-deny but cannot grant; this makes the security argument a
subset property that a test can check (design §4.2, ATT-8).

**D3. Fail closed on everything that is not a positive, fresh result.** Verifier down, timeout,
unparseable answer, unknown state, state 4 (retry), missing age: deny, each with a distinct audit
reason. Justification: RFC 9334 §8.4 default posture; the RFC gives no outage rule
(`[RFC9334 §5.1, §8.4]`), so we state one.

**D4. A positive result requires state 3 and a bounded age.** `max_age` is part of project policy.
If the released Keylime API exposes no per-agent timestamp (`[VERIFY]`), the options are: ask
upstream; or an *observed-age* mode that is audit-labelled as weaker; or do not ship. Decision
needed. Justification: RFC 9334 §10 and Appendix A.1 make freshness the Relying Party's job.

**D5. Requester binding.** The prototype uses a client certificate issued by the Keylime
certificate-package flow (CN = agent UUID), pinned by Keyorix (option B1). The documented claim
is limited accordingly (design §4.3); B2 (AK-signed nonce) is the target for the funded phase.
Justification: a verdict about a node is otherwise unrelated to who is asking.

**D6. No override past attestation in iteration 1.** Whether break-glass may bypass the gate is a
trust-model change and is deferred. Justification: an override that exists makes every
attestation claim conditional on its audit and review controls.

**D7. Verifier credential and transport.** mTLS, pinned CA, short timeouts, circuit breaker;
breaker open means deny.

## Consequences

- Gated secrets become unreadable whenever the verifier is down or the agent is failing;
  documented, not mitigated (design §7, ATT-4/5).
- Routine OS updates change PCR/boot-log state; operators must stage the Keylime policy before
  rollout, and recovery from FAILED appears to need an operator re-add (`[VERIFY in lab]`).
- A software-TPM lab validates protocol behaviour only; no hardware-trust claim until the
  physical-TPM run.
- A positive result does not by itself prove the requester is the attested node (ATT-2).
- Keylime becomes an optional operated dependency (Python services + agent per host) next to a
  single Go binary.

## Alternatives considered

- **Build our own verifier** on `go-tpm-tools` `server.VerifyAttestation` (already in `go.mod`):
  rejected for now; it is a one-shot quote check with a caller-supplied trusted AK and gives
  none of enrolment, scheduling or policy (design §6). Reopen if D4 cannot be satisfied.
- **Keylime secure payload only** (Keylime delivers; Keyorix is a payload source): different
  product, bypasses Keyorix authorization and audit; rejected for the gate use case.
- **Verdict as a signed token the node presents (passport pattern, RFC 9334 §5.1):** Keylime does
  not issue one today (`[KL-enh:121]` lists it as possible future); revisit if it does.

## Open questions

See design §12 (D1 to D8 there are the decisions this ADR needs answered, with
recommendations).
