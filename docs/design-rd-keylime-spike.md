# Keylime comparison spike: attestation-gated secret release

Status: **draft for decision. Design only; nothing was run.** The lab part is **pending e2e VM**
(see §8). Nothing here is accepted until Andrei approves it, and no production path changes
before then. The gating mechanism proposed in §5 has its own ADR,
[ADR-116](adr-116-attestation-gated-secret-release.md), status Proposed.

Session RD-KEYLIME-SPIKE-1, 2026-10-23, against origin/main `760e92e32` (docs only).

## 0. How to read the sources

Every behaviour or number below carries one of these tags. Anything without a tag is Keyorix's
own design, i.e. a proposal.

| Tag | Meaning |
|---|---|
| `[KL-docs:<page>]` | Read in this session from `keylime/keylime-docs` (master), pages `design/overview`, `design/threat_model`, `user_guide/secure_payload`, `user_guide/use_measured_boot`, `user_guide/user_selected_pcr_monitoring`, `installation`, `rest_apis`, `security` |
| `[KL-code:<file>]` | Read in this session from `keylime/keylime` (master): `keylime/common/states.py`, `keylime/db/verifier_db.py` |
| `[KL-enh:<n>]` | Read in this session from `keylime/enhancements` (proposals, **not** shipped behaviour): 103 push model, 121 verify-evidence API, 98 SPIRE integration |
| `[RFC9334 §x]` | Read in this session (verbatim quotes, via a read-only fetch sub-agent) from the RFC text |
| `[repo:<path>]` | Read in this session in the Keyorix tree |
| `[VERIFY]` | Not established from text read in this session. Must be checked in the lab or against the Keylime release in use before anyone relies on it |

Source caveats, stated up front:

- The Keylime docs repo is partly stale. The installation page still says Python 3.7 and
  `m2crypto`, and says the Rust agent is "in early stages" `[KL-docs:installation]`, while
  `keylime/rust-keylime` is a live Apache-2.0 repository (last push 2026-09-25, GitHub API,
  read in this session) and `keylime/keylime` is Apache-2.0 with latest release v7.14.3
  (2026-07-06). Which agent is the supported default today is `[VERIFY]`.
- The master-branch DB model has fields the REST page does not document (§3.3). Whether release
  v7.14.3 returns them is `[VERIFY]`.
- The brief names RFC 9334 clauses; the fetch showed the brief's numbering was off. Roles are in
  §4.1, artifacts §4.2, patterns §5, trust model §7, freshness §10, security §12. This note uses
  the numbers from the text.

## 1. Summary

- **Verdict: hybrid.** Adopt Keylime for everything that is hard and already exists: TPM identity
  enrolment, nonce-fresh quote verification, boot-log replay and policy, IMA runtime policy,
  continuous re-attestation, revocation notices. Build only a small Keyorix-side relying-party
  adapter and the gate. Do **not** build an appraisal engine (§6).
- **What Keylime does not give us, and the gate must supply:** (a) a signed, portable
  attestation result. The documented REST answer is an unsigned JSON status over mTLS
  `[KL-docs:rest_apis]`; signing a result is listed as a possible future addition in
  enhancement 121 `[KL-enh:121]`. (b) A freshness timestamp in the documented response (§3.3).
  (c) Any link between "the node with agent UUID X is in policy" and "the party asking Keyorix
  for the secret is that node" (§4.3). (c) is the real limit of the whole approach and is stated
  as a residual risk, not hidden.
- **Honest novelty statement:** attestation itself is not new, and neither is releasing a secret
  after attestation: Keylime's own secure-payload mechanism does exactly that, with the verifier
  holding one key share `[KL-docs:secure_payload]`. What this prototype can claim is narrower:
  the verdict becomes a **deny-only, audited, fail-closed condition inside a secrets manager's
  existing authorization and audit-before-disclosure path** (§5), with specified behaviour for
  verifier outage, stale evidence and PCR drift. Any wider "first to" claim is `[VERIFY]` and
  should not go in the memoria técnica without a literature check.
- **Nothing was measured.** Deployment effort below is counted from the documented components
  and prerequisites, not from a timed run. No numbers appear in this repo doc.
- Open decisions for Andrei: §12.

## 2. Scope and non-goals

In scope: the comparison, the integration design with Keyorix as relying party, the failure-mode
table, the lab plan and the demo script, input text for the funded D3 proposal.

Out of scope: product code, a CLI, a threshold or multi-verifier design, IMA policy authoring,
anything in `.github`. R7 (`tpm` KEK provider with PCR policy) is a separate item; §9 says how
they relate.

## 3. What Keylime is, as documented

### 3.1 Components `[KL-docs:design/overview]`

| Component | Role | Notes |
|---|---|---|
| Agent | Runs on the attested host; talks to the TPM; produces quotes, serves UEFI and IMA event logs | Python agent in the docs; Rust agent (`rust-keylime`) exists `[VERIFY which is default]` |
| Registrar | Enrolls agents: receives EK public key, EK certificate, AK public key; binds AK to EK with `MakeCredential` / `ActivateCredential` | Registrar agent endpoints are "unprotected by design" `[KL-docs:rest_apis]` |
| Verifier | Pulls quotes from enrolled agents continuously, validates them, can send revocation messages | Pull model; push model is a proposal `[KL-enh:103]` |
| Tenant | CLI (`keylime_tenant`) to add/remove agents, check EK certs, deliver payloads | Operator tool, not a service |

### 3.2 Security model `[KL-docs:design/threat_model]`

- Hardware (CPU, memory, board) is trusted; the TPM is the root of trust, checked through the EK
  or EK certificate. UEFI Secure Boot firmware and CRTM are trusted.
- The network adversary can drop, modify and forge messages. The attested OS and the agent are
  **not** trusted until first successful attestation, and are attested continuously afterwards.
- Detected: TPM quote manipulation (EK validation, AK enrolment with enforced key properties,
  verifier nonce in each quote), boot-chain modification (static PCR policy, or UEFI event-log
  policy engine), runtime file integrity (IMA).
- Software TPMs (swtpm) are treated "the same as a hardware TPM" from the VM side. The EK
  certificate of a software TPM chains to a local CA (the registrar example shows a
  `swtpm-localca` EK cert `[KL-docs:rest_apis]`), so the manufacturer-CA check is meaningless for
  swtpm: **a swtpm lab proves the protocol, not hardware trust.** The later physical-TPM run is
  the only evidence for the hardware-rooted claim.

### 3.3 Verdict surface (what a relying party can read)

`GET /v2.0/agents/{id}` on the verifier returns, among config fields, `operational_state`,
`severity_level`, `last_event_id`, and also the `v` key share `[KL-docs:rest_apis]`.
States `[KL-code:states.py]`:

| Value | Name | Meaning (source docstring) |
|---|---|---|
| 0 | REGISTERED | in registrar, not added to verifier |
| 1 | START | added to verifier, will move on |
| 2 | SAVED | added, waiting |
| 3 | GET_QUOTE | "under periodic integrity checking" |
| 4 | GET_QUOTE_RETRY | periodic checking, "in a retry state due to connection issues" |
| 5 / 6 | PROVIDE_V / _RETRY | receiving the V key (retry on connection issues) |
| 7 | FAILED | "failed to prove the integrity" |
| 8 | TERMINATED | will be removed |
| 9 | INVALID_QUOTE | "integrity report ... not trusted against whitelist" |
| 10 | TENANT_FAILED | terminated but removal failed |

Consequences for a relying party:

1. **Only state 3 can mean "currently passing", and even it carries no age.** State 4 is neither
   pass nor fail: the verifier cannot reach the agent. The gate must treat 4 as not-passing.
2. **The documented response has no "last successful attestation at" field.** The master DB model
   does: `last_successful_attestation`, `last_received_quote`, `attestation_count`,
   `consecutive_attestation_failures`, `accept_attestations` `[KL-code:verifier_db.py]`. Whether
   the released API exposes them is `[VERIFY]`. If it does not, the gate cannot bound staleness
   from the verifier alone and needs either a Keylime patch or its own observation (§5.4).
3. **Reactivation:** `APPROVED_REACTIVATE_STATES` is START, GET_QUOTE, GET_QUOTE_RETRY,
   PROVIDE_V, PROVIDE_V_RETRY `[KL-code:states.py]`. FAILED is not in the list, so recovery from
   a failed state appears to need an operator re-add, not an automatic return `[VERIFY in lab]`.
   This is good for security (no self-healing after a failed integrity check) and bad for
   availability after a benign OS update (§7).
4. The verifier response includes the `v` share. Anyone with a verifier client certificate can
   read it `[KL-docs:rest_apis]`. A Keyorix verifier credential must be scoped to read-status
   `[VERIFY: whether Keylime offers per-endpoint authorization at all; the docs show one CA
   for "add/delete/list"]`.

### 3.4 PCR policy styles `[KL-docs:design/overview, use_measured_boot, user_selected_pcr_monitoring]`

- Static `tpm_policy` (PCR allowlist): "fragile because they change if something in the boot chain
  is updated (firmware, Shim, GRUB, Linux kernel, initrd, ...)". PCR 1 can differ per machine
  on netboot because it encodes the NIC MAC.
- Measured-boot policy engine over the UEFI event log: the preferred method; the verifier replays
  the boot log against PCRs [0-9], [11-14] and compares to a reference state under a policy.
  The default `measured_boot_policy_name` is `accept-all`, "just don't try to match the contents".
  **A deployment that enables measured boot with an empty reference state and `accept-all`
  checks only log-to-PCR consistency.** That is a silent weak configuration; ATT-6 (§10).
- IMA runtime attestation against an allowlist or signatures (not studied further here).

## 4. Integration design: Keyorix as relying party

### 4.1 Role mapping `[RFC9334 §4.1, §5]`

| RATS role | Here |
|---|---|
| Attester | Host running the Keyorix client / agent workload, with its (sw)TPM and the Keylime agent |
| Verifier | Keylime verifier (+ registrar for enrolment) |
| Relying Party | Keyorix server: applies its own Appraisal Policy for Attestation Results ("require state 3, age <= T") to release or refuse a secret |
| Relying Party Owner | Keyorix admin who sets the gate policy per project/secret |
| Verifier Owner | Platform admin who sets the Keylime policy (PCRs, boot policy) |

Pattern: RFC 9334 §5.2 (Background-Check) has the Relying Party obtain a result from the Verifier.
Keylime differs in that the verifier pulls evidence itself instead of the relying party
forwarding it, so this is a **standing-verifier variant of the Background-Check shape**: the
relying party queries a result, it does not carry evidence. RFC §5.3 allows such combinations.
The RFC §8.4 default, "By default, the Relying Party does not believe the Attester to be
compliant", is the posture the gate adopts.

### 4.2 Where the verdict gates release

On the secret-read path of an identity marked `attested` (proposal; name not final):

```
request ──> authenticate ──> core.Authorize (RBAC, as today)
                               │ allow
                               ▼
                     AttestationGate.Check(identity, project policy)
                               │ pass                     │ deny / error
                               ▼                          ▼
                  audit-before-disclosure          audit (deny + reason), 403,
                  (verdict recorded)               no value, no partial value
                               ▼
                       decrypt + return
```

Properties (to be made machine-checked in the implementation, §11):

- **Deny-only.** The gate runs after authorization and can only turn an allow into a deny. It
  never grants. A bug in the gate can over-deny; it cannot widen access. (Test shape: for every
  gate outcome, the set of allowed requests is a subset of what RBAC alone allows.)
- **Fail closed.** Any error, timeout, unparseable answer, unknown state or missing field is a
  deny. No `AllowWeakerFallback`-style escape; that flag exists for key providers
  `[repo:docs/security/threat-models/secret-storage-key-hierarchy.md KEY-2]` and must not be
  imitated here.
- **Audit-before-disclosure applies to the verdict.** The record carries the agent UUID, the
  state value read, the evidence age, the policy id, and the reason. Same invariant text as
  `[repo:docs/adr-115-local-audit-journal.md]`: no value leaves before its audit record is durable.
- **Gate-unavailable never degrades to "attested = true".** Verifier down is a deny (§7).

### 4.3 The binding problem (the honest limit)

The verifier answers a question about **the node with agent UUID X**. The secret request arrives
from **some caller with some credential**. Nothing in the verdict ties the two together. A caller
who steals the machine credential from a compromised node and replays it from elsewhere gets a
pass as long as the real node X is still attested and healthy. The same holds for a node that is
compromised *after* its last good quote and before the next one.

Options to bind the requester to the attested node, in increasing strength:

| Option | Mechanism | Closes | Does not close |
|---|---|---|---|
| B0 | Verdict check only, bearer machine token | nothing about theft | token replay from another host |
| B1 | Machine identity authenticates with a client certificate whose CN is the agent UUID, issued by a CA the Keylime tenant created for certificate-package delivery; Keyorix pins that CA | A stolen *token* is useless without the cert; cert is delivered only after the first successful attestation `[KL-docs:secure_payload]` (CN = agent UUID) | Cert private key sits in the node's tmpfs `[KL-docs:secure_payload]`; root on the node can copy it |
| B2 | Keyorix issues a fresh nonce; the node's AK signs it; the verifier or Keyorix checks the signature against the enrolled AK. This is the shape of the SPIRE proposal `[KL-enh:98]` | Replay from another host: the AK cannot leave the TPM | Needs a Keylime API that is proposed, not shipped `[VERIFY]`, and client-side TPM code |
| B3 | TPM-resident TLS/identity key (key never exported) | Strongest | New client component; out of scope for a spike |

Recommendation: spike on B1 and document B0 as the explicit baseline; flag B2 as the target for
the funded phase. The prototype must **not** claim that a pass means "this request came from the
attested machine" under B0 or B1. Under B1 the honest claim is "the caller holds a credential
that Keylime issued to a node that was attested at issue time, and that node is attested now".

### 4.4 Freshness and caching `[RFC9334 §10]`

RFC §10 names three approaches: nonces, synchronized timestamps and epoch IDs, and notes
"always a race condition possible" for results. In Keylime's pull model the verifier handles
freshness of *evidence* with its own nonce per quote `[KL-docs:design/threat_model]`. What the
relying party needs is freshness of the *result*. Design:

- Gate policy has `max_age`. The gate passes only if `now - last_successful_attestation <= max_age`
  using a timestamp taken from the verifier response if the release exposes one `[VERIFY]`.
- If it does not, the gate may use its own observation: it polls state and records the instant it
  last saw state 3 immediately following a sequence of observations. That is weaker (it measures
  "verifier said 3 at my poll", not "a quote was verified at T") and must be labelled so in the audit
  record. The ADR makes this a decision (D4).
- A cached pass is valid for at most `max_age`, never longer, and never across a state change
  notification. No negative caching beyond a short backoff, to avoid hammering a failing verifier.
- Clock: results are timestamped by the verifier, compared with Keyorix's clock. RFC Appendix A.1
  requires roughly synchronized clocks in the timestamp pattern, with the threshold covering
  maximum skew `[RFC9334 App. A.1]`. Skew handling is a decision (D4).

## 5. Proposed gating mechanism (summary of ADR-116)

1. A per-project (later per-secret) policy `require_attestation` naming a verifier, an agent
   binding, a `max_age`, and allowed states (default: {3}).
2. A machine identity can be bound to exactly one agent UUID at creation by an admin; the binding
   is audited.
3. The gate is called after `core.Authorize` on read of covered secrets, deny-only, fail-closed.
4. Verifier connection: mTLS, pinned CA, short timeouts, per-verifier circuit breaker. Breaker
   open = deny, with a distinct audit reason.
5. A loud alert (existing notification path) when a previously passing identity transitions to
   fail, and a metric per verdict class. No new alerting machinery is proposed.
6. No automatic fallback, no "break-glass past attestation" in the first iteration. Whether an
   emergency override exists is a decision (D6): it is a trust-model change.

## 6. Build versus adopt

Keylime facts are from §3; Keyorix facts from the repo. Effort is **counted components**, not
a timed run.

| Capability | Adopt Keylime | Build in Keyorix | Notes |
|---|---|---|---|
| TPM quote verification with nonce | Yes `[KL-docs:design/threat_model]` | Library exists: `go-tpm-tools` `server.VerifyAttestation` checks AK trust, signature, `TPM_GENERATED`, PCR digest, nonce, event log vs PCRs `[repo: ~/go/pkg/mod go-tpm-tools v0.4.10 server/verify.go]`; already a dependency `[repo:go.mod]` | Build-side is a **one-shot** verifier: you supply the trusted AK |
| EK to AK binding at enrolment (MakeCredential / ActivateCredential) | Registrar `[KL-docs:design/overview]` | Not provided by `VerifyAttestation`; `import_certify.go` is a different flow `[VERIFY]` | Build = write and security-review an enrolment protocol |
| EK certificate chain check (manufacturer CAs, custom steps) | Tenant `[KL-docs:design/threat_model]` | Library helper `VerifyAKCert` for AK certs `[repo: verify.go]` | |
| Continuous re-attestation, retry states | Verifier loop and state machine `[KL-code:states.py]` | Scheduler + state machine + persistence | Largest hidden cost of building |
| Boot-log replay and policy | Policy engine `[KL-docs:use_measured_boot]` | Event-log parsing exists in go-tpm-tools; the policy language does not | |
| IMA runtime policy | Yes `[KL-docs:user_guide/runtime_ima]` (title only; page not studied) | No | Out of scope either way for the spike |
| Revocation notices to peers | Yes, signed, certificate-package mode `[KL-docs:secure_payload]` | No | Peer-facing; not needed for server-side gating |
| Signed attestation result token | **No** (future idea in 121 `[KL-enh:121]`) | Could sign our own verdict record | Our audit record is the artifact we control |
| Relying-party gate, audit, RBAC mapping | No | **Yes, necessarily** | The Keyorix-specific part |
| Operational footprint | Python verifier + registrar + DB (SQLite default; PostgreSQL etc. supported) + agent on each host `[KL-docs:installation]` | Zero extra services | Keyorix is a single Go binary today |
| Licence | Keylime and rust-keylime Apache-2.0 (GitHub API, read in session) | n/a | Separate processes; no linking into the AGPL dual-licensed binary (the model is in `[repo:docs/adr-080-agpl-dual-licensing-model.md]`, title only; not read in detail) `[VERIFY by Andrei: no licensing concern in running Apache-2.0 sidecars]` |
| Maintenance signal | Active: pushes within weeks, v7.14.3 on 2026-07-06, CNCF project (repo description) | Ours forever | |
| Failure behaviour | Documented states; retry vs failed distinction `[KL-code:states.py]` | We define it | |
| Security review burden | Upstream, plus our integration | All ours | Every trust/crypto item needs Andrei's ADR approval first |

Conclusion: building the verifier means re-implementing the registrar, the polling state machine
and the boot-log policy engine to reach parity with the part of Keylime we would use. Building
the gate is unavoidable. Hence **hybrid**.

What would flip the verdict to *build*: Keylime's verdict surface cannot give a bounded-age
result (§3.3 item 2) and upstream will not add it; or the operational footprint is unacceptable
for the target customers (air-gapped single binary installs). What would flip it to *adopt only*
(no Keyorix gate, use secure payload): the customer wants delivery to the node, not release from
Keyorix. That is a different product (Keyorix would be a payload source).

## 7. Failure behaviour

All rows describe the **proposed gate**; the "Keylime says" column is from the sources above and
is `[VERIFY]` in the lab (§8) before being relied on.

| Situation | Keylime says | Gate behaviour | Audit / alert |
|---|---|---|---|
| Verifier down or unreachable | n/a | Deny. RFC 9334 §5.1 names the unavailable verifier as a failure mode but gives no rule `[RFC9334 §5.1]`; §8.4 default is distrust | Audit reason `verifier_unreachable`; alert if sustained |
| Verifier slow | n/a | Deny after the timeout; breaker opens after N failures | `verifier_timeout`; metric |
| Answer unparseable / unknown state / missing field | n/a | Deny | `verdict_unparseable` |
| State 3, age <= `max_age` | Periodic checking `[KL-code:states.py]` | Pass | Verdict recorded |
| State 3 but age unknown | Documented response has no timestamp `[KL-docs:rest_apis]` | Deny unless policy sets `age_source=observed` (D4) | `age_unknown` |
| State 3, age > `max_age` (stale) | Verifier may simply be slow or backlogged | Deny | `attestation_stale` |
| State 4 (retry, connection issues) | `GET_QUOTE_RETRY` `[KL-code:states.py]` | Deny: neither pass nor fail | `agent_unreachable_from_verifier` |
| PCR drift (kernel or firmware update, config change) | Quote fails policy; state moves to FAILED(7) or INVALID_QUOTE(9) `[VERIFY exact]`; no documented automatic return | Deny. Recovery is an operator decision: update the Keylime policy, re-add the agent | `attestation_failed`; alert on pass-to-fail transition |
| Verifier restarted / DB lost | Persistence is a stated concern (enhancement "persist agent restart" exists `[KL-enh: filename 1_persist_agent_restart.md; contents not read]`) | Deny until agents re-enrol | `agent_unknown` |
| Agent re-enrolment with a new AK after reboot | "The Keylime agent currently generates an AK on every startup" `[KL-docs:design/overview]` | After reboot, deny until the verifier re-appraises; expect a gap | `attestation_pending` |
| Clock skew between Keyorix and verifier | n/a | Deny if beyond configured skew bound | `clock_skew` |

Availability cost is real: a healthy fleet becomes unable to read gated secrets whenever the
verifier is down. This is the price of fail-closed and it must appear in the customer-facing
documentation of the feature, together with the recommendation to run the verifier with the
same HA expectations as the Keyorix server `[VERIFY: Keylime verifier HA story, enhancement
22 "enhanced scalability" exists but was not read]`.

## 8. Lab plan (pending e2e VM)

Not run. The task states the e2e VM is reserved and the Mac has no TPM or Docker. (`COMMON-RULES`
dated 2026-10-17 says HEAD2HEAD-1 is finished and the VM is free; this brief, dated later,
says reserved and scopes the session to design. The brief was followed. Whoever runs the lab
should confirm availability with `kssh e2e` first.)

Environment: e2e VM, directory `~/work/RD-KEYLIME-SPIKE-1`, every container, volume and process name
prefixed `rdkl-`. Clean up only those names. Processes through `spawn.sh` with a TTL.

Steps, each with the expected observation and the claim it checks:

1. Start `swtpm` in socket mode; point `TPM2TOOLS_TCTI` at it (`mssim:port=...`
   `[KL-docs:installation]`). Check: `tpm2_pcrread` works.
2. Start registrar and verifier from the official images (published on the Keylime GitHub
   packages page per `[KL-docs:installation]`) and the agent (pin the exact versions used and
   record them in the report). Check: agent registers; registrar shows EK cert, AK.
3. Enrol with a static `tpm_policy` over a PCR the test can extend, then repeat with a
   measured-boot reference state. Check: state reaches 3 (GET_QUOTE).
4. **Positive path:** a stub Keyorix gate (shell + `curl` with mTLS to `GET /v2.0/agents/{id}`)
   releases one test secret. Check: release only when state is 3; record which of
   `last_successful_attestation` etc. the released API actually returns (§3.3 item 2).
5. **PCR drift:** `tpm2_pcrextend` a monitored PCR. Check: state leaves 3, which state, how it is
   reported, whether the verifier recovers by itself (§3.3 item 3), and the observed detection
   delay (record in the report only, not in the repo).
6. **Verifier down:** stop the verifier container. Check: gate denies; restart; observe how
   long the agent takes to be re-appraised.
7. **Agent unreachable:** block verifier-to-agent traffic. Check: state 4, then what.
8. **Stale:** hold the verifier but delay the agent. Check: whether age is observable.
9. **Binding (B1):** deliver a certificate package via the tenant; confirm CN = agent UUID
   and that it appears only after attestation `[KL-docs:secure_payload]`.
10. **Deployment-effort record:** the operator keeps a log of steps, commands and surprises;
    the report counts steps and notes every doc/behaviour mismatch (the §0 caveats are the first
    suspects). This is the "deployment effort" evidence, not a stopwatch.
11. Second run on one physical TPM machine (outside this session; per the plan the physical
    TPM run is the only hardware-trust evidence).

Pass criteria for the spike: steps 4 to 8 behave as §7 predicts or the discrepancy is written
into §7 and the report.

## 9. Relationship to R7 (TPM-sealed KEK)

Different problem. R7 protects the **KEK at rest on the Keyorix host**: the TPM refuses to unseal
off-host or under a changed PCR state; enforcement is local and offline. R10 protects **release
to a remote node**: enforcement is a remote verifier's appraisal and works online.
The existing provider is host-bound only, with no PCR policy
`[repo:internal/crypto/tpm_provider.go header]`; its stated reasons for deferral (boot chain not
owned, no recovery path) apply with more force to R10, where PCR drift is the normal case rather
than an upgrade accident (§7). R10 does not depend on R7 code. If both exist, the server's own
PCR-sealed KEK and the clients' attestation are independent layers; do not describe one as
implying the other. The RD-TPM-SEAL-1 brief was read; its ADR was not yet on origin when this
was written, so no cross-citation of its numbers is made. The RD-PQWRAP-1 design (PR #3662,
fetched read-only as `dep-3662`) is cited only for conventions: sourced-claim tagging and the
statement that the KEK providers are symmetric.

## 10. Threat-model rows (proposed)

These are **not** added under `docs/security/threat-models/`: `go test ./internal/threatmodelcheck`
requires every row of a new document to cite an existing `Test`/`Fuzz` function
`[repo:internal/threatmodelcheck/evidence_test.go]`, and no test exists yet because this item is
design only. They move into `docs/security/threat-models/attestation-gated-release.md` with the
implementation, each row paired with a red/green test (§11). Evidence column here names the test
**to be written**.

| ID | STRIDE | Description | Proposed mitigation | Test to write | Residual |
|---|---|---|---|---|---|
| ATT-1 | Spoofing | A network attacker answers the verifier query with a fake "state 3" | mTLS to a pinned verifier CA; no plaintext fallback | gate refuses a verifier presenting an unpinned certificate | Compromise of the verifier or its CA is total (RFC §7.1 assumption that the Verifier is not compromised) |
| ATT-2 | Spoofing | Machine credential stolen from a node and used elsewhere while the real node stays healthy | B1 client certificate bound to agent UUID; B2 later | request with a valid token but no matching client cert is denied | **Open.** Root on the attested node can copy the credential (§4.3) |
| ATT-3 | Repudiation / Tampering | Stale pass reused after the node left policy | `max_age`; no cache beyond it; transition alert | cached pass expires at `max_age`; state change invalidates | Detection delay is bounded by Keylime's polling interval `[VERIFY]` plus `max_age` |
| ATT-4 | DoS | PCR drift after a routine OS update denies a whole fleet | Deny by design; documented operator procedure; staged policy updates before rollout | gate denies on FAILED; recovery procedure documented | Availability cost accepted; no override in iteration 1 (D6) |
| ATT-5 | DoS | Verifier outage denies all gated reads | Fail closed with distinct audit reason; circuit breaker; HA guidance | verifier-down yields deny and audit row, never allow | Customer must run the verifier highly available |
| ATT-6 | Tampering | Verifier configured with `accept-all` measured-boot policy or empty reference state, giving a pass that checks little | Gate policy declares the minimum assurance it requires (e.g. policy engine non-default); doc warning | gate rejects a verifier whose reported policy is the default `[VERIFY: whether the API reports it]` | If the API does not report policy, this stays a documentation control (stated plainly) |
| ATT-7 | Information disclosure | Verifier credential read from the REST API exposes the `v` share of every agent | Least-privilege verifier credential `[VERIFY: possible?]` | n/a until the lab answers | Possibly unmitigable on the Keyorix side |
| ATT-8 | Elevation | Gate bug turns a deny into an allow | Deny-only structure: gate runs after `Authorize` and its result is AND-ed | property test over gate outcomes: allowed set subset of RBAC-allowed set | None identified at design level |
| ATT-9 | Repudiation | Disclosure without a record of which verdict allowed it | Verdict in the audit-before-disclosure record | read with a failing audit write returns no value | Inherits the chain's own residuals |
| ATT-10 | Spoofing | swtpm lab results presented as hardware-rooted trust | Memoria text states software TPM proves protocol only; physical run required | n/a (documentation control) | The claim must wait for the physical-TPM run |

## 11. Implementation plan for the next session (commits)

Precondition: Andrei's decisions D1 to D7 in §12 and ADR-116 moved to Accepted. Until then no
code.

1. `docs`: threat model `attestation-gated-release.md` rows ATT-1..10 with `GAP` markers where
   the test is not there yet (the checker requires a test per row; each GAP row cites an existing
   test, per `threatmodelcheck` rules), and README index line.
2. Red tests: gate unit tests with a fake verifier: allow only on state 3 and age <= `max_age`;
   deny on every other state, timeout, malformed body, unknown state value. Property test:
   gate-allowed is a subset of RBAC-allowed. Red first.
3. `internal/attest` (proposed package name): verifier client (mTLS, pinned CA, timeouts, circuit
   breaker), verdict type, no business logic. Package `INVARIANTS.d/` fragments for deny-only,
   fail-closed, audit-before-disclosure.
4. Gate wiring on the read path after `Authorize`, behind a config flag default off; audit field
   additions; metrics.
5. Machine identity to agent-UUID binding, admin-audited.
6. CLI/API: `project attestation set|show`, `machine bind-agent` (shape in the demo); OpenAPI,
   CLI and web callers updated together per the "never build one side of a contract" rule.
7. Lab journey on the e2e VM against real Keylime (steps §8 turned into a script with `rdkl-`
   names), CI job optional.
8. Docs and changelog fragment; threat-model rows turned from GAP to tested.

Hot-files note: step 4 touches wiring files; keep it the last, tiny commit.

## 12. NEEDS ANDREI (open decisions)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Adopt Keylime as the verifier, hybrid with a Keyorix gate (vs build vs delivery-only) | Hybrid |
| D2 | Requester binding for the prototype: B0, B1 or B2 | B1 for the spike; B2 as the funded-phase target; never claim more than §4.3 |
| D3 | Treat state 4 and "age unknown" as deny | Yes, deny |
| D4 | Freshness source if the released API has no timestamp: patch upstream, observed-age mode, or refuse to ship | Ask upstream first; allow observed-age mode only with the weaker audit label |
| D5 | Gate is deny-only, after Authorize, fail-closed, no weaker-fallback flag | Yes |
| D6 | Emergency override past attestation (break-glass) in iteration 1 | No in iteration 1; revisit with break-glass design owners |
| D7 | Licence comfort with running Apache-2.0 Keylime as a separate process and documenting it | Yes; Andrei to confirm |
| D8 | ADR number 116 (may collide with RD-TPM-SEAL-1) | Take next free at merge time; `check-adr-numbers` will catch it |

## 13. One-page brief for the memoria técnica

**Problem.** A secrets manager normally releases a secret to whoever holds a valid credential.
A stolen credential, or a machine whose boot chain or runtime was altered, still gets the
secret. We want release to depend on **verified platform state**.

**Approach.** Keyorix acts as the relying party of the IETF RATS architecture (RFC 9334). An
open-source attestation verifier (Keylime, Apache-2.0, CNCF) checks the host's TPM quote,
boot log and, optionally, runtime integrity. Keyorix asks the verifier for the current result
before returning a secret, and releases the value only on a positive, fresh result.

**What is ours.** The gate: deny-only (it can never widen access), fail-closed (any error is a
refusal), audited before disclosure (the verdict is in the hash-chained audit record), and
specified behaviour for verifier outage, stale evidence and platform drift after an update.

**What is not ours and we say so.** Attestation, quote verification, enrolment and policy engines
are Keylime's. Releasing a secret after attestation is already a Keylime feature (secure
payload). The contribution is the integration with a secrets manager's authorization and audit
model, and the documented failure semantics.

**Result at this stage.** Design and comparison complete; nothing executed. A software-TPM lab
plan (swtpm) exists and checks protocol behaviour only. Hardware-rooted trust requires the
planned run on a physical TPM and is **not claimed**.

**Known limits, stated.** A positive result proves the node with a given identity is in policy.
It does not by itself prove the requester is that node (replay of a stolen credential from
another host); the prototype narrows this with a certificate issued only after attestation and
leaves the full fix (a key that cannot leave the TPM) to the funded phase. Availability depends
on the verifier; a fleet cannot read gated secrets when it is down, by design.

**Evidence to attach when the lab runs:** the §8 step log, the observed state transitions, the
gate's red/green tests, the audit records of allow and deny.

## 14. Input text for the funded D3 Phases 2 to 4 proposal (public-repo-safe)

Wording only; no strategy, no budget, no dates.

> **Verified platform state and trust-gated delivery.** Keyorix will make the release of a secret
> conditional on the verified state of the requesting platform. Phase 2 establishes platform
> state: measured boot and TPM-backed host identity, evaluated by an independent verifier. Phase 3
> adds remote attestation as a relying party in the RATS architecture (RFC 9334), with a
> deny-only, fail-closed gate integrated into the existing authorization and tamper-evident audit
> path. Phase 4 covers an attested agent runtime, where the credential presented to the secrets
> manager is bound to a key that cannot leave the TPM, closing the replay gap that a verdict
> alone leaves open.
>
> **Preliminary finding (design-level comparison, 2026).** An existing open-source verifier
> (Keylime) already provides enrolment, quote verification, boot-log policy and continuous
> re-attestation. The project therefore adopts it for appraisal and concentrates its own
> engineering on (a) the relying-party gate and its failure semantics, (b) a bounded-freshness
> result, which the verifier's documented interface does not currently expose, and (c)
> requester-to-platform binding. These three are the technical risk and the innovation claim; the
> attestation mechanism itself is not claimed as new.
>
> **Validation.** A software-TPM laboratory validates protocol behaviour; a physical-TPM
> campaign provides the hardware-rooted evidence. Measurements are reported in the project
> deliverables, not asserted in advance.

## 15. New versus state of the art

- **Not new:** TPM quotes, remote attestation, the RATS architecture, continuous attestation,
  releasing a payload after attestation (Keylime secure payload `[KL-docs:secure_payload]`),
  attestation as an input to an authorization decision (SPIRE proposal `[KL-enh:98]`,
  one-shot enrolment story in `[KL-enh:121]`).
- **Possibly new, to be checked:** a verdict as a deny-only condition inside a secrets manager's
  RBAC and audit-before-disclosure chain; stated freshness semantics for the result.
  Whether other secrets managers do this is `[VERIFY: literature and product survey not done
  in this session]`.
- **Not claimed:** hardware trust (software TPM only), protection against a compromised
  attested node using its own credentials, post-quantum properties of the TPM signature
  algorithms `[VERIFY]`.

## 16. Technical risks

1. Verdict has no bounded age in the documented API (§3.3). Medium to high; lab answers it.
2. Binding gap (§4.3). High; inherent; mitigated, not closed.
3. Availability coupling to the verifier (§7). Medium; product decision.
4. Upstream drift: docs are partly stale; push model and new APIs are proposals. Medium.
5. Operational weight: three Keylime services plus agents, versus a single Go binary today.
   Medium for the target market; cannot be judged until the lab step log exists.
6. Weak configuration silently accepted (`accept-all`, empty reference). Medium; ATT-6.
7. swtpm results mistaken for hardware trust. Low if the wording in §13 is kept.
8. FAILED needing operator re-add (§3.3 item 3) turns routine updates into incidents. Medium.
