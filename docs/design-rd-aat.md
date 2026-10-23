# Design note: attenuating agent tokens (RD-AAT-1)

Status: R&D design, ADR-116 **Proposed**. Nothing here is implemented. The prototype and
the SMT model were throwaway and are not in the repo. This note records what they
checked and how to rebuild them.

## 1. What it is for

Agents delegate. An orchestrator asks a worker to read one secret, the worker should
get authority for that secret only, for minutes, and nobody should be able to widen
it on the way, including the worker. AATs (draft-niyikiza-oauth-attenuating-agent-tokens-02,
see ADR-116 for the source and its [VERIFY]) do this offline: each holder signs a
narrower child for the next holder; any verifier with Keyorix's public key checks the
chain.

```
Keyorix (root issuer, online once)
   | root AAT: secrets.read ref one_of {payments/production/db-password, …}, 15 min, depth 2
   v
Orchestrator agent ── derives offline ──> child AAT: ref exact payments/production/db-password, 5 min, terminal
                                             | held by keyorix-mcp (key outside the model's reach)
                                             v
                                  keyorix-mcp presents chain + PoP per tool call
                                             v
                         Keyorix server = enforcement point
                         Section 8 in process -> root not revoked, principal active
                         -> AATRestriction on ctx -> Authorize chokepoint (∩ live RBAC)
                         -> ledger intent record (durable) -> value -> outcome record
```

An offline verifier (`keyorix aat verify`, a stdlib Go package) runs the same Section 8
with a trust-anchor file and no network.

## 2. Keyorix profile of the draft

| Draft element | Keyorix value | Notes |
|---|---|---|
| root `iss` | the server's issuer URL (config) | must equal the trust anchor's issuer (step 3k) |
| trust anchor | dedicated Ed25519 AAT issuer key, KEK-wrapped, published with `kid` | rotation overlap = max root lifetime |
| `cnf.jwk` (root) | key from `req_cnf`, possession proved by a signed challenge | draft leaves the proof mechanism open |
| tool identifiers | `<iss>/tools/secrets.read`, `<iss>/tools/secrets.list` | exact-string match, no normalisation (draft 3.3.1) |
| `secrets.read` args | `ref`: `project/environment/name`, required | same format as keyorix-mcp |
| `secrets.list` args | `environment`, optional | |
| constraints (v1) | `exact`, `one_of` on `ref`; `one_of` on `environment` | `keyorix_ref_glob` designed, off (ADR-116 decision 6) |
| `del_max_depth` | default 2, max 4 at issuance; verifier accepts up to 8 | 8 is the draft's interop floor |
| lifetime | root default 15 min, max 1 h | children can only be shorter (I3) |
| `aud` / `aat_aud` | server audience URL; `aat_aud` required at the server | blocks replay at another verifier |
| PoP `jti` | tracked for every `secrets.read`, shared across replicas | draft step 7i |
| `authorization_details` other types | ignored, carry no authority | draft 3.3 |
| `sub` | absent; principal comes from the root record Keyorix keeps | draft omits `sub` on purpose |

Example root payload (Keyorix profile, JCS-serialised before signing):

```json
{"authorization_details":[{"tools":{
   "https://keyorix.example/tools/secrets.list":{"environment":{"constraint_type":"one_of","optional":true,"values":["production","staging"]}},
   "https://keyorix.example/tools/secrets.read":{"ref":{"constraint_type":"one_of","values":["payments/production/db-password","payments/production/stripe-key","payments/staging/db-password"]}}},
  "type":"attenuating_agent_token"}],
 "cnf":{"jwk":{"crv":"Ed25519","kty":"OKP","x":"…orchestrator key…"}},
 "del_depth":0,"del_max_depth":2,"exp":1793000900,"iat":1793000000,
 "iss":"https://keyorix.example","jti":"019a…"}
```

A child keeps one tool, sets `ref` to `exact`, `del_max_depth` 1, `exp` 5 minutes, a new
`cnf.jwk` (the draft requires a new holder key across a process boundary),
`iss = urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint of the parent key>` and
`par_hash` = SHA-256 of the parent's JWS signing input.

### 2.1 `keyorix_ref_glob` (designed, not enabled)

- Grammar: exactly three `/`-separated segments; each is a literal with no `* ? [ \`,
  `*`, or `literal*`.
- `check(v)`: `path.Match(pattern, v)` (what `KEYORIX_MCP_ALLOWED_REFS` already uses).
- `subsumes(parent, child)`, per segment: parent `*` admits any child segment; parent
  literal `L` admits only child literal `L`; parent `P*` admits a child literal or
  `Q*` with `P` a prefix of it, never a child `*`. Linear time.
- Cross-type pairs with core types: parent `keyorix_ref_glob` subsumes a child `exact`
  or `one_of` whose every value matches it (a finite check, sound by construction because
  each value goes through the parent's own `check`; not in the SMT model); no core
  parent subsumes a child glob except `wildcard`.

## 3. Verification at the Keyorix server

1. Parse the presentation from the body or gRPC metadata (size limits first, step 2).
2. Run Section 8 steps 1-7 in process. On any failure: deny with a generic error to the
   caller (as MCP-4 / ADR-096) and audit the step and reason.
3. Root `jti` not revoked, root principal active: local lookups (Keyorix issued the root).
4. Build an `AATRestriction` from the leaf (tool → permission, `ref` → scope + name) and
   put it on the request context. `Authorize`/`AuthorizePrincipal` apply it first, then
   resolve the root principal's live roles. `IsGlobalAdmin` and `RequireRole` deny for
   any AAT request (the ADR-042 pattern).
5. PoP `jti` record (insert-or-nothing, read back) — step 7i runs last, after every
   other check, as the draft orders it.
6. Ledger intent record durable → value → outcome record (R6).

The restriction is a filter: if the leaf names a secret the principal has since lost
access to, nothing is granted.

## 4. Monotonicity, machine-checked: the SMT encoding sketch

The runtime check is structural (draft 4.5). The SMT model proves that those structural
rules are sound, meaning a child that passes them never accepts anything its parent
rejects, and that every rule is needed. Each obligation is one SMT-LIB query; a PROOF
expects `unsat` for "the rule says the child attenuates, the child accepts x, the parent
rejects x". A MUTANT weakens one rule and expects `sat`.

**A. Core table, universal over every parameter.** Example, `range` under `range`
(real-valued bounds, optional, with inclusivity):

```smt2
(declare-const x Real)  ; plus phasMin pmin pincMin phasMax pmax pincMax, same for c…
(assert (=> phasMin (and chasMin (or (> cmin pmin) (and (= cmin pmin) (not (and cincMin (not pincMin))))))))
(assert (=> phasMax (and chasMax (or (< cmax pmax) (and (= cmax pmax) (not (and cincMax (not pincMax))))))))
(assert (and (=> chasMin (ite cincMin (>= x cmin) (> x cmin))) (=> chasMax (ite cincMax (<= x cmax) (< x cmax)))))
(assert (not (and (=> phasMin (ite pincMin (>= x pmin) (> x pmin))) (=> phasMax (ite pincMax (<= x pmax) (< x pmax))))))
(check-sat) ; unsat
```

Set-valued types (`one_of`, `not_one_of`, `contains`, `subset`, `exact` under `one_of`)
use an abstract value sort with sets as `(Array V Bool)`, where equality means equal JCS
serialisation, e.g. `contains`: `(subset P C) ∧ (subset C A) ∧ ¬(subset P A)` is unsat.

**B. `all` / `any`.** Clause truth at one value as booleans `P_i`, `Q_j`; `m_ij` = "the
recursive check said child clause j ⊑ parent clause i", which by induction gives
`Q_j → P_i`. `all`: `∀i ∃j m_ij` plus `∧Q` plus `¬∧P` is unsat; `any`: `∀j ∃i m_ij` plus
`∨Q` plus `¬∨P` is unsat. Swapping the two matching rules is sat (caught). Deeper trees
follow by structural induction on depth (bounded by `MAX_CONSTRAINT_DEPTH`).

**C. Constraint-map key rules** (closed world, `optional`, `"*"`, new in -02). Keys
`k1..k3` plus `u` (any name neither map names); per key: named, optional, value
satisfies; `"*"` is a wildcard. Child accepts ∧ rules ∧ parent rejects is unsat; removing
any one of the five key rules is sat (each rule is load-bearing).

**D. Chain bounds.** Eight links unrolled with I2/I3 per link: the leaf never outlives
the root and depth never passes the root's `del_max_depth`. Dropping
`del_max_depth ≤ parent's` at one link is sat.

**E. `keyorix_ref_glob`.** Regex membership with a symbolic literal (`str.to_re p`) made
z3 time out, so segments are encoded without regexes: a segment has no `/`; `*` is
`true`, literal `L` is `(= s L)`, `P*` is `(str.prefixof P s)`. Each accepted
(parent kind, child kind) pair is proved for all literals. The whole-ref proof needs
"a split on `/` is unique": z3 times out, cvc5 proves the two-segment lemma, three
segments follow by applying it twice.

**F. Issuance against RBAC** (reuses the RD-SMT-SPIKE-1 Keyorix-side model: a grant is
`(project, environment | all)`). `∃ ref ∈ pattern: ¬granted(project(ref), env(ref))`.
`payments/production/*` is unsat; `payments/*/db-password` is **sat** when the
principal has only production and staging grants (any later environment), which is why
ADR-116 decision 4 refuses environment globs without an environment-0 grant.

### Results (counts, no timings)

| Part | Proofs (unsat) | Mutants / widenings (sat) |
|---|---|---|
| A core table | 7 | 6 mutants + `not_one_of` under `one_of` shown unsound |
| B all/any | 2 | 2 |
| C map key rules | 1 | 5 |
| D chain bounds | 1 | 1 |
| E ref glob | 7 (6 segment pairs + cvc5 lemma) | 2 |
| F issuance | 2 | 3 real widenings with witnesses |

All 40 obligations gave the expected verdict (20 unsat, 20 sat). z3 decided all of them
except the split lemma, where it timed out; that is recorded as such and the lemma is
proved by cvc5. cvc5 1.4.2 gave the same verdict as z3 on
the 29 queries it accepts (the array-as-set queries use z3 syntax).

**What the model does not cover:** JCS and number admissibility (tested by the vectors
instead); the cryptographic invariants I1, I5, I6 (signature checks, tested by vectors);
that the Go code implements the rules the model encodes (tested by the vectors and the
property test below, not by the solver).

## 5. Prototype (throwaway, outside the repo)

A stdlib-only Go verifier of Section 8 (strict JSON with duplicate rejection, number
admissibility, JCS, Ed25519, every DENY labelled with its step and reason), a deriver
that refuses to sign a widening child with the same reason, and a demo.

- Published draft-02 vectors (`tests/vectors/aat-jws-vectors.json` in the draft's
  repository, 224 vectors: 52 PERMIT, 172 DENY): **224/224 verdicts and 224/224 first
  failing steps**. The first run had 3 step mismatches (an RSA or short key in `cnf.jwk`
  accepted until the PoP step); the fix validates the holder key at 3l/4b2.
- Five planted subsumption bugs: four flip a verdict on the vectors, one (a child adding
  `"*"`) is still denied by a later check and shows only as a step change.
- `keyorix_ref_glob` property test against `path.Match` (400,000 random pattern pairs,
  about 55,000 accepted as subsumed, about 10,000 matching refs checked): no unsound pair.
  A planted bug (prefix test reversed) fails it at once.
- Demo output (the acceptance criterion): every widening is refused with a traceable
  reason, by the deriver and again by the enforcement point:

```
forced widened child (extra ref) at the EP     DENY  step 4p4  token 1 widens: tool keyorix_get_secret: argument "ref": one_of does not subsume one_of: values not a subset of the parent's (I4)
forced child adds keyorix_rotate_secret        DENY  step 4p1  token 1 adds tool "keyorix_rotate_secret" the parent does not authorize (I4 widening)
forced child outlives its parent               DENY  step 4h   token 1 outlives its parent: exp 1793001800 > 1793000900 (I3)
forced grandchild past del_max_depth           DENY  step 4e   token 2 del_depth 2 > parent del_max_depth 1 (I2)
mallory replays worker's chain with own PoP    DENY  step 7b   pop signature does not verify under leaf cnf.jwk (I6)
```

(The prototype used bare MCP tool names; the profile above uses issuer URIs.)

## 6. Ledger fields (R6 link)

The intent record for an AAT read carries: root `jti` and issuer `kid`; per token the
SHA-256 of its signing input; leaf holder key thumbprint; PoP `jti` and `iat`; tool;
`ref`. Never the value, never `hta` beyond `ref`. A denied presentation is recorded with
its step and reason. The export keeps the chain bytes (authorization metadata, not a
secret: a stored AAT is useless without its holder key, the draft notes) so `verify` can
rerun Section 8 offline. Field mapping to EU AI Act Art. 12 belongs to the ledger ADR
(RD-AGENT-LEDGER-1), not here.

## 7. Implementation plan (next session, after ADR-116 is accepted)

One PR per concern, each green on its own; the verifier lands first because everything
else depends on it.

1. `pkg/aat`: strict JSON, JCS, admissibility, constraints (`check`, `subsumes`), Section 8
   verifier returning step + reason. Tests: the draft-02 vector file vendored under
   `testdata/` with its source and SHA-256; subsumption pair table including every
   MUST-reject pair; fuzz target on the verifier input; mutation check.
2. `pkg/aat`: deriver (`Derive(parent, key, child)`) refusing non-attenuating children with
   the verifier's reason; property test: derive random narrowings, verify passes; random
   widenings, verify denies at the matching step.
3. Issuer key: generation, KEK wrapping, `kid`, key-set endpoint and export file;
   rotation overlap; config leaves (`internal/config` + surface leaves file).
4. Root issuance endpoint for machine identities: `req_cnf` challenge, request-as-parent
   attenuation, decision-4 RBAC ceiling (syntactic rule + table test derived from the
   SMT cases), root record + revocation; OpenAPI + CLI + web follow the contract rule.
5. Server enforcement: presentation parsing (body / gRPC metadata), `AATRestriction` at the
   chokepoint, `IsGlobalAdmin`/`RequireRole` fail closed, PoP `jti` table (insert or
   nothing), generic errors, audit of denials; family-wide test that every value-read route
   honours the restriction; fault-injection rows for the `jti` write.
6. `keyorix aat verify|derive|inspect` CLI (offline) + journey: issue → derive → read →
   widen denied → revoke root → denied.
7. `keyorix-mcp` holder mode: leaf key file, PoP per tool call, `KEYORIX_TOKEN` not needed
   in this mode; MCP threat rows updated.
8. Ledger intent/outcome records for AAT reads (after the R6 ADR is accepted).
9. `docs/formal/aat/`: the SMT model (parts A-F) with a non-CI runner, like `docs/formal/smt`.
10. Threat-model rows AAT-1..AAT-14: replace each GAP with the test that lands.
