# ADR-120: Attenuating agent tokens (offline delegation that can only narrow)

**Status:** Proposed (2026-10-23). Design only; nothing is implemented.
**Date:** 2026-10-23
**Number:** 120 (approved by Andrei, 2026-10-23). The four sibling R&D drafts are
numbered 116 = signed audit checkpoints (#3665), 117 = TPM-sealed KEK (#3667),
118 = agent evidence ledger (#3668), 119 = attestation-gated secret release (#3666).
**Context:** R&D item RD-AAT-1. Design note with the prototype results, the SMT
encoding and the implementation plan: [`design-rd-aat.md`](design-rd-aat.md).
Threat rows: [`security/threat-models/agent-delegation-tokens.md`](security/threat-models/agent-delegation-tokens.md).
Demo script (future CLI): [`demo/attenuating-agent-tokens.md`](demo/attenuating-agent-tokens.md).

**Source of the external format.** IETF Internet-Draft
`draft-niyikiza-oauth-attenuating-agent-tokens-02` ("AAT"), dated 2026-10-20. It was
read in this session from the author's source file
(`github.com/tenuo-ai/tenuo`, `ietf/draft-niyikiza-oauth-attenuating-agent-tokens-02.md`,
SHA-256 `a44a309a…87bb`), because the sandbox cannot reach ietf.org. **[VERIFY]** that
the datatracker copy of -02 matches. Statements below about the draft come from that
text. Statements about the RFCs it builds on (RFC 9396 RAR, RFC 7800 `cnf`, RFC 8693
token exchange, RFC 9449 DPoP, RFC 7638/9278 thumbprints, RFC 8785 JCS) repeat what the
draft says about them. Those RFCs were not read here, so each is **[VERIFY]**.

## Context

An AI agent that reads secrets usually holds one broad credential: a machine token
(ADR-030) or a PAT (ADR-042). When a task fans out (an orchestrator, then a planner,
then a tool-calling worker), every hop carries the whole credential. The MCP threat
model already records this: MCP-2 ("the token is scoped too broadly") has only the
operator's discipline as a control, and MCP-3 (prompt injection) is bounded only by
what the token can reach.

ADR-042 lets a user mint a narrower PAT. That needs a round trip to Keyorix for
every narrowing, and the narrowed PAT is a bearer token: whoever copies it can use
it. Neither property suits agents that delegate many times per task, sometimes
without network access to Keyorix.

The AAT draft defines a JWS-signed token. Its holder can derive a child token
offline with equal or narrower authority. Any enforcement point that holds the root
issuer's public key can verify the whole chain offline. Authority is a set of
`(tool, argument constraints)`. Six invariants make each link narrower or equal:
holder-signed links (I1), depth (I2), lifetime (I3), capability subsumption (I4),
parent hash (I5) and proof of possession per invocation (I6).

## Decision

Each item states the decision and why.

1. **Adopt the AAT -02 JWS profile unchanged, with no Keyorix-specific wire format.**
   Tokens, the PoP JWT, the presentation object and the Section 8 verification
   algorithm follow the draft. *Why:* the draft ships byte-exact test vectors.
   Conformance can therefore be tested, not asserted. The RD-AAT-1 prototype verifier
   matches all 224 published vectors, both the verdict and the first failing step
   (design note, "Prototype"). A private format would need its own cryptographic
   review and would not interoperate.

2. **Keyorix is the root issuer.** It signs root tokens with a dedicated Ed25519
   issuer key that is used for nothing else. The key is wrapped by the KEK hierarchy
   like other server keys. The public half is published as a key set with `kid`, and
   as an export file for air-gapped verifiers. Rotation keeps the old and the new key
   in the trust-anchor set for one maximum root lifetime. *Why:* the draft leaves
   trust-anchor management to deployments. A key that only signs AATs limits the
   damage if it leaks, and the overlap makes rotation possible without downtime.

3. **A root token is an agent session in AAT form.** The agent evidence ledger
   design (ADR-118, RD-AGENT-LEDGER-1, open as PR #3668) makes an agent a
   machine identity of type `agent`. Each run is an agent session, started by a
   delegator who holds `agents.delegate`. The session scope is capped by the agent's
   roles and by the delegator's permissions at that moment. Issuing a root AAT is
   starting such a session, with the same checks and the same
   `agent.session_started` row:
   - the root `jti` is the session id;
   - `authorization_details` is the session scope;
   - `exp` is at most the session's `expires_at`.

   The request also carries `req_cnf`, as the draft says, and the holder proves
   possession of that key by signing a Keyorix challenge. In v1 only agent sessions
   hold roots; non-agent machine identities (for example CI) do not (Decision A2).
   *Why:* there is then one delegation model, not two. The ledger already derives the ceiling
   from the actor (CLAUDE.md, "a ceiling that inspects only the target is not a
   ceiling"). AAT adds only what a session credential lacks: holder binding, and
   narrowing offline across hops.

4. **The root never exceeds the session ceiling, for any secret name,
   including names created later.** Issuance treats the request as the parent and the
   session ceiling as the cap (decision 3). It refuses a `ref` pattern that covers a
   project or environment where that ceiling holds no `secrets.read`, unless it holds
   `secrets.read` at environment 0 (all environments). *Why:* an offline
   enforcement point cannot consult Keyorix RBAC, so the root is the only ceiling it
   sees. The SMT model shows the case that sampling misses: `payments/*/db-password`
   issued to a principal with grants on `payments/production` and `payments/staging`
   also covers an environment created next month (witness `payments/A/db-password`).

5. **Tools and arguments (v1, read-only like ADR-061):** the tool identifiers are
   `<issuer>/tools/secrets.read` and `<issuer>/tools/secrets.list`. `secrets.read`
   takes one argument, `ref` (`project/environment/name`, the keyorix-mcp ref
   format). `secrets.list` takes an optional `environment`. Each tool maps to exactly
   one Keyorix permission, and `ref` maps to the authorization scope. No tool writes,
   rotates or deletes. *Why:* the draft asks for URI tool identifiers. A URI under
   the issuer's own URL needs no registration. Read-only matches the MCP server's
   reviewed v1 surface (MCP-6).

6. **v1 uses only the draft's core constraint types** for `ref` (`exact`,
   `one_of`). A Keyorix extension type, `keyorix_ref_glob`, is designed: its `check`
   is `path.Match`, and its subsumption procedure is syntactic and runs in linear
   time. The SMT model proves the procedure sound for every pattern of its grammar.
   It stays disabled in v1 (Decision A1). *Why:* the draft says a chain
   with an unregistered extension type is not conformant, and verifiers that lack
   the type fail closed. Shipping it unregistered would break interoperability with
   any third-party verifier.

7. **At the Keyorix server, a verified chain only narrows the session's live
   authority.** The server runs Section 8 in process, with no lookup per derived
   token. It then checks that the root's session is `active` and that the agent
   identity and the delegator are still active. These are local lookups, because
   Keyorix issued the root. It turns the
   leaf's capability into a restriction carried on the request context. That
   restriction is enforced first at the `Authorize`/`AuthorizePrincipal` chokepoint,
   exactly like the ADR-042 PAT restriction. `IsGlobalAdmin` and `RequireRole` fail
   closed for AAT requests, as they already do for restricted PATs. The effective
   authority is therefore C(leaf) ∩ roles(agent) ∩ permissions(delegator, now). This
   is the ledger's per-intent rule, with the leaf in place of the session scope.
   *Why:* this reuses the one authorization chokepoint every path already goes
   through (ADR-042's reasoning). It also brings back what the draft gives up, which
   is revocation: revoking the session, suspending the agent or the delegator, or
   removing a grant takes effect on the next request.

8. **Verifying offline anywhere** uses a stdlib-only Go package and
   `keyorix aat verify --trust-anchors <file>`. Neither contacts Keyorix. These
   verifiers apply the draft's semantics only (no live RBAC). For them, revocation
   means short lifetimes (decision 9). A status list is later work
   (draft-ietf-oauth-status-list, **[VERIFY]**). *Why:* this is the acceptance
   criterion "chain verified offline", and it is honest about what offline loses.

9. **Limits.** The enforcement point accepts `MAX_DELEGATION_DEPTH` 8 (the draft's
   interoperability floor). Keyorix issues roots with `del_max_depth` 2 by default
   and at most 4. The root lifetime defaults to 15 minutes and is at most 1 hour.
   `MAX_IAT_SKEW` is 30 s, the PoP window ±30 s, `MAX_TOKEN_SIZE` 64 KiB,
   `MAX_CHAIN_SIZE` 256 KiB and `MAX_CONSTRAINT_DEPTH` 32 (the draft's recommended
   values). *Why:* the draft makes every limit finite and implementation-defined.
   Short roots bound the damage when a holder key is stolen (the draft gives no
   re-keying).

10. **Replay.** For every `secrets.read`, the server records each accepted PoP `jti`
    in shared storage: an insert that does nothing on conflict, then a read-back,
    never catching the conflict (the Postgres rule in CLAUDE.md). Each `jti` is kept
    for the PoP window. `aat_aud` must name the server. *Why:* the draft requires
    `jti` tracking for tools with side effects, and recommends it for tools whose
    responses are sensitive. A secret value is the most sensitive response Keyorix
    has. All replicas must share the state (draft step 7i).

11. **Strict parsing is part of the security boundary.** Claims, arguments and the
    PoP are parsed with duplicate member names rejected and numbers kept exactly as
    written (admissibility check). Signatures are verified over the bytes exactly as
    presented. The verifier allows only `Ed25519`: it rejects `EdDSA`, `none`, keys
    supplied in headers and any `crit` it does not understand. *Why:* the draft
    requires each of these. Go's `encoding/json` silently keeps the last duplicate
    key, so the verifier must not use it for claims (the prototype has its own strict
    parser, and vectors in the 3b/4b/6b/7b groups need it).

12. **Presentation transport.** The chain and the PoP travel in a request body or in
    gRPC metadata, never in an HTTP header: chains exceed common header limits (the
    draft's note). For MCP, `keyorix-mcp` becomes the leaf holder. It holds the leaf
    private key outside the model's reach, signs one PoP per tool call, and presents
    to the server. The orchestrator derives a per-task leaf for it. This replaces a
    broad `KEYORIX_TOKEN`. *Why:* the draft's guarantees hold only while the holder
    key is out of the model's reach. A process boundary is the cheapest such
    boundary that already exists.

13. **A verified presentation is the ledger intent (R6 link, ADR-118, PR #3668).** The
    ledger asks for an intent before every release. That is normally a separate
    `POST …/intents` call followed by a header on the read. For an AAT read, the
    server instead writes the `agent.intent` row from the verified presentation.
    The row has one target (the `ref`), the tool URI, `max_uses` 1, and `not_after`
    set to the end of the PoP window. The hashed `diff` carries the chain evidence:
    each token's signing-input digest, the leaf holder key thumbprint and the PoP
    `jti`. The row is written through the same audited-mutation writer, in a
    transaction that commits before the value is released. If the audit append
    fails, no value is released. The ledger's outcome record follows. A denial is
    audited with its Section 8 step and reason. The export keeps the chain bytes, so
    an auditor can rerun Section 8 offline. The value is never recorded. A leaf may
    carry a signed `purpose_code` claim, which is recorded if present (Decision A6).
    *Why:* audit-before-disclosure is non-negotiable (ADR-118 and ADR-115
    state it). The PoP is already a fresh, per-call signed statement of what the
    agent is about to do, so a second round trip adds nothing. Delegation happens
    offline, so the chain presented at use time is the only record of who delegated
    to whom, and every holder signed it.

14. **SMT is a design-time and review tool, not a runtime dependency.** The runtime
    runs only the draft's polynomial structural checks (the draft requires that of
    every subsumption procedure). The SMT model (z3, with cvc5 as a cross-check)
    proves the following sound:
    - the core subsumption table;
    - the all/any combinator rule;
    - the constraint-map key rules;
    - the chain bounds;
    - the `keyorix_ref_glob` procedure;
    - the issuance rule of decision 4.

    Each rule is also shown to be needed: a mutant with that rule weakened is
    satisfiable. In CI, the vectors and Go property tests carry the guarantee. The
    solver model runs outside CI, like `docs/formal/smt` (RD-SMT-SPIKE-1).

## Monotonic attenuation, stated once

For a chain `root = T0, …, Tn = leaf` accepted at time `t`:
`C(Tn) ⊆ … ⊆ C(T0) ⊆ roles(agent) ∩ permissions(delegator, issuance)`. At the Keyorix
server, effective authority is `C(Tn) ∩ roles(agent) ∩ permissions(delegator, t)`.
At an offline verifier it is `C(Tn)`, so
everything that offline verification buys rests on the issuance-time inclusion
(decision 4).

## New vs state of the art

- **Macaroons** (HMAC chains, contextual caveats), **SPKI/SDSI** (delegation
  certificates, reduction by intersection), **Biscuit** (public-key blocks and
  Datalog checks) and **UCAN** (content-linked delegations) all attenuate offline.
  The AAT draft compares itself with them, and these descriptions come from the
  draft. **[VERIFY]** against the primary sources. RFC 8693 token exchange narrows
  only through the authorization server.
- The draft's author ships a reference implementation (Tenuo, CBOR envelope) with
  property-based tests of monotonicity and 224 JWS vectors. This is the closest
  prior art. It does not make a secrets manager the issuer.
- What is new here, as far as this session found (a GitHub search, no literature
  review; **[VERIFY]**):
  1. **A secrets manager as root issuer and enforcement point.** The draft's
     offline chain is intersected with live RBAC at the chokepoint every request
     already passes. That restores the revocation the draft gives up, without
     tracking derived tokens.
  2. **Machine-checked soundness of the draft's I4 rules.** These are the core
     subsumption table, the all/any matching rule and the -02 optional/`"*"` key
     rules. They are proved for all parameter values, and each rule is shown to be
     needed. The draft asks implementers to publish such independent analyses.
  3. **Universal issuance-time containment against RBAC.** It holds for every
     present and future secret name, reusing the RD-SMT-SPIKE-1 encoding, where
     earlier checks only sampled existing names.
  4. **Delegation evidence that verifies offline**, inside the agent evidence ledger
     export.

## Technical risks

- **The draft is young and changing.** Between -01 and -02 it made breaking changes
  (explicit `typ`, `Ed25519` instead of `EdDSA`, `aat_hash`, the optional/`"*"`
  arguments). Pin one revision, and keep the vectors as the conformance test.
- **The extension type registration is undecided** (whether to use an IANA registry
  or a URI type is open in the draft). This keeps `keyorix_ref_glob` off in v1
  (decision 6, Decision A1).
- **The holder key is within the model's reach.** If the agent process can read its
  own key, every token bound to that key is usable at full scope. Decision 12 moves
  the key into `keyorix-mcp`. A compromised agent host is still out of scope (see
  the threat rows).
- **There is no re-keying** (draft section on holder key compromise). A parent stays
  usable after delegating, until it expires. Short roots and per-hop fresh keys
  bound the damage. They do not remove it.
- **Parser differentials.** Duplicate keys, number precision and JCS details decide
  verdicts (whole vector groups test them). A wrong JSON library breaks I4 without
  any crypto failing.
- **Solver fragility.** z3 times out on the lemma that a ref splits uniquely on `/`.
  cvc5 proves it at once. The model therefore depends on two solvers, and the CI
  guarantee must come from tests, not from the solver.
- **FIPS mode.** Whether `crypto/ed25519` is approved inside the Go FIPS 140-3 module
  is **[VERIFY]**. AAT is off under `KEYORIX_FIPS_MODE` until that is verified, or
  until ES256 is added (Decision A5).
- **No post-quantum signature.** The draft makes Ed25519 mandatory, and no ML-DSA
  JOSE profile is assumed here (**[VERIFY]** the JOSE registrations). Root lifetimes
  are short, so the exposure is to forging new roots, not to harvesting old ones.
- **Replay state is cross-replica shared state on the read path.** It adds a
  write per secret read. It needs the same atomicity and fault-injection coverage as
  other check-then-act paths.
- **Not mitigated by AATs, as the draft states:** misuse inside the authorized scope,
  exfiltration through authorized arguments, and a compromised enforcement point or
  issuer.

## Consequences

- An orchestrator can hand a worker a five-minute token for one secret, offline,
  and the worker cannot widen it, re-delegate past the depth limit, outlive the
  parent, or let anyone else use it.
- Every widening attempt is rejected with a Section 8 step and a reason that names
  the dimension that widened (for example
  `4p4: tool …/secrets.read: argument "ref": one_of does not subsume one_of`).
- New code: a verifier package, an issuer endpoint, a context restriction at the
  chokepoint, a PoP `jti` table, an MCP holder mode and ledger records. The commit
  plan is in the design note.

## Decisions (Andrei, 2026-10-23)

Andrei answered all six open questions on 2026-10-23, each as recommended, with no
conditions beyond the ADR numbering above. The status stays **Proposed** (approved to
implement as Proposed). The letters A1-A6 are referred to from the Decision section.

- **A1. `keyorix_ref_glob`: v1 ships the core constraint types only (`exact`,
  `one_of`).** *Reason:* the draft makes a chain with an unregistered extension type
  non-conformant, and third-party verifiers fail closed on it. *Obligation:* keep the
  glob designed but disabled, and request registration later with the SMT soundness
  proof (part E) as evidence. A private Keyorix-only glob does not ship.
- **A2. Only agent sessions (the ADR-118 `agent` identity type) hold a root AAT in
  v1.** *Reason:* root issuance is agent-session start and reuses the ledger's
  delegator ceiling. A plain machine identity would need its own ceiling rule and has
  no delegator. *Obligation:* issuance refuses any principal that is not an agent
  session. Non-agent machine identities (CI, services) are a later ADR.
- **A3. The server records every accepted PoP `jti` for `secrets.read` in shared
  storage, on every read (insert or nothing, retention equal to the PoP window).**
  *Reason:* it is cross-replica and needs no extra round trip, unlike an
  enforcement-point nonce. The draft requires it for side-effect tools and
  recommends it for sensitive responses. *Obligation:* decision 10 stands as written,
  with the atomicity and fault-injection coverage listed under the technical risks. No
  server-nonce alternative in v1.
- **A4. Tool identifiers are issuer-URL URIs** (`<issuer>/tools/secrets.read`,
  `<issuer>/tools/secrets.list`), not bare MCP tool names. *Reason:* the draft says
  tool ids should be URIs and compares them as exact strings, and bare names collide
  across agents. *Obligation:* `keyorix-mcp` maps its tool names to these URIs; the
  comparison stays exact-string.
- **A5. AAT is off under `KEYORIX_FIPS_MODE` until Ed25519's status in the Go FIPS
  140-3 module is confirmed.** *Reason:* the draft makes Ed25519 mandatory and its FIPS
  approval in Go's module is unverified. *Obligation:* the issuer and verifier refuse
  to start in FIPS mode with a clear message (fail closed). They are enabled only after
  a verified result, or after ES256 is added.
- **A6. A leaf may carry an optional signed `purpose_code` claim.** It is recorded in
  the ledger intent row if present; otherwise the tool URI alone is recorded.
  *Reason:* ADR-118 intents carry an operator-defined `purpose_code`. Draft-02
  passthrough claims carry no authority, but the deriver signs them, so they are
  usable as evidence. *Obligation:* the claim never widens authority and is never
  required. It is evidence only.
