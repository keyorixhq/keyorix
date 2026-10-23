# Design note: SMT check that migrated Keyorix grants never exceed the Vault policy

Status: R&D spike (RD-SMT-SPIKE-1), not a product feature. Code: `docs/formal/smt/`.
Relates to ADR-114 (Vault access-model migration), whose governing rule is "round down,
always: a migrated grant is a subset of what Vault granted, never a superset".

## Context

ADR-114's rule is checked today in two ways: unit tests of the mapping rules in
`migrate/internal/accessplan`, and end-to-end equivalence checks
(`scripts/vault-migration-testbed/access_equivalence_test.go`, step 6 of
`scripts/demo/vault-migration-demo.sh`) that compare Vault's `sys/capabilities-self`
with Keyorix for the secrets that exist in one seeded Vault. Both are sampling: they
check the paths someone listed, for the operation someone thought of (`read`). Neither
says anything about a secret created tomorrow, or about `list`, metadata, or writes.

The spike asks whether an SMT solver can answer the rule as a universal statement, per
migrated role: *is there any request at all (operation, mount, secret name) that Keyorix
would allow and Vault would deny?*

## Decision (for the spike)

Encode both sides in SMT-LIB 2.6 (logic `QF_SLIA`: strings, regular expressions, linear
integers), solve with an off-the-shelf solver through its CLI (z3; the same files run on
cvc5), and generate the inputs from the real code rather than by hand.

### Encoding

- **Universe = logical operations on a KV secret**, not raw Vault paths: read value,
  list names, read metadata, create, update, delete. Each becomes a different Vault
  request per KV version (v2 values live under `<mount>/data/`, listing and metadata
  under `<mount>/metadata/`) and one Keyorix permission (`secrets.read`, `.write`,
  `.delete`) on the secret's project and environment. Comparing path strings directly
  would hide exactly the data/metadata split that turned out to matter.
- **Secret names are unconstrained strings**: a directory part (`""` or segments ending
  in `/`) plus a non-empty leaf without `/`. UNSAT therefore covers every name,
  including ones that do not exist yet.
- **Vault rule matching is regular-expression membership** (exact path: equality; `+`
  segment: any run of non-`/` characters; trailing `*`: any suffix).
- **Vault's rule selection is resolved before the solver runs.** Vault picks one rule
  per request: an exact match first, otherwise the highest-priority glob by its
  documented "priority matching" order (first wildcard later, then not ending in `*`,
  then fewer `+` segments, then longer, then lexicographically larger). That order
  depends only on the pattern strings, so it is computed in Python and emitted as one
  `ite` chain: the first matching rule decides, and `deny` in that rule denies.
  Policies attached to one role are merged as Vault merges them (same path: union of
  capabilities, `deny` wins). A `deny` on a broader glob does **not** override a more
  specific allow; the encoding follows Vault here, not the shorthand "deny always
  overrides".
- **Keyorix side**: a secret's scope is the project/environment its import run
  (`keyorix-migrate vault --vault-mount/--vault-path → --project/--environment`) put it
  in, taking the longest matching import prefix. A grant covers it when the project
  matches and the grant's environment is that environment or 0 (all environments).
  A name no import covers is not in Keyorix and is never Keyorix-allowed.
- **Split encoding.** The obvious encoding (one query, operation and mount as solver
  variables) works on small policies but stops finishing at a few dozen rules. The
  check is therefore split into one query per (mount, operation, import run). The split
  is exact, not an approximation: the import that owns a name is unique, so the parts
  partition the name space; inside a part the Keyorix verdict is a constant (a part
  Keyorix denies needs no query); and the request path has a known literal prefix, so
  rules whose literal head is not prefix-compatible with it can never match and are
  dropped from that part's `ite` chain. One more step is stated to the solver as a
  rewrite: an import prefix that ends in `/` is a prefix of the name if and only if it
  is a prefix of the directory part. Without it, z3 spent minutes on a query that is
  otherwise trivial.

### Inputs come from the code

`migrate/internal/accessplan/smt_model_export_test.go` is the only producer of the
solver's inputs (`docs/formal/smt/cases/*.model.json`). It extracts each policy's text
from the file that seeds a real Vault (the vault-migration testbed's `seed.sh`, the
migration demo, journey 4, the shipped health-scan policy), parses it with the same
`healthscan.ParsePolicyHCL` the migration uses, and runs `NewPathMapper` +
`BuildPolicyItems` to get the grants. A committed model that no longer matches the code
or the seed scripts fails `go test` in `migrate/`, so the solver cannot silently check a
stale copy of the mapping.

### How the encoding itself is checked

1. Reference semantics: a concrete Python evaluator of Vault's ACL selection, tested
   against the rules in Vault's documentation (exact beats glob, each priority rule,
   same-path merge, deny scope, the `list` trailing-slash case).
2. Differential test: about 1,700 (rule set, concrete request) pairs, the solver's
   verdict against the reference evaluator.
3. Split vs. single-query encoding: same verdicts and same widened operations on every
   case and on small synthetic ones.
4. Every counterexample the solver returns is re-checked by both concrete evaluators
   (Vault denies, Keyorix allows) before it is reported.
5. Mutation check (`mutation_check.py`): eight planted encoding bugs (priority order
   reversed, `+` crossing `/`, deny skipped, list trailing slash, metadata treated as
   data, environment-0 grants dropped, unsound rule slicing, longer import not
   excluded) are each caught by the tests.
6. Second solver: cvc5 gives the same verdicts as z3 on every case from the same files.

Not yet done: comparing the reference evaluator with a running Vault.
`docs/formal/smt/vault_oracle.py` does that (`sys/capabilities-self` on every
counterexample and on probes around every rule), but it needs Vault in a container and
is pending on the e2e VM.

## Results (qualitative; timings are in the spike report, not here)

The 10 cases, 8 of them from real seeded policies:

| Case | Policy source | Verdict |
|---|---|---|
| testbed-approle-migrator | testbed `mig1-glob-readonly` | widens: `list` and metadata |
| testbed-glob-plus-deny | testbed glob + `mig1-deny-prod` | subset (no grant: deny-overlap) |
| testbed-templated | testbed `mig1-templated` | subset (no grant: templated) |
| demo-ci-payments-reader | demo `payments-readonly` | **widens: reads secrets outside payments/** |
| demo-finance-batch-job | demo `payments-readonly` + `payments-deny-db` | subset (no grant: deny-overlap) |
| demo-k8s-deployer | demo `mobile-readwrite` | **widens: reads and writes payments secrets** |
| journey4-n4-readonly | journey 4 `n4-readonly` | widens: `list` and metadata |
| healthscan-scanner | `migrate/healthscan-policy.hcl` | subset (no grant: mount management) |
| constructed-exact-path | constructed, one exact secret path | widens: the whole environment |
| constructed-metadata-list-only | constructed, `list` on `metadata/` | widens: browse becomes read |

Every whole-case "subset" verdict on the real policies is vacuous: the migration
proposed no grant at all, so the solver confirmed only that nothing was granted. The
non-trivial proofs are per operation. For `testbed-approle-migrator` and
`journey4-n4-readonly`, reading secret values is proved within the Vault policy for
every name (the read parts are UNSAT); only listing and metadata widen. Each real
migration that grants anything widens in at least one operation.

### The counterexample, explained

The migration demo seeds `secret/data/payments/{stripe,db}` and
`secret/data/mobile-app/firebase`. The AppRole `ci-payments-reader` holds only
`path "secret/data/payments/*" { capabilities = ["read","list"] }`. The demo imports
the whole `secret/` mount into one Keyorix project/environment and maps access with
`--path-map secret/data=<project>:<environment>`. `PathMapper.Resolve` matches the
override by plain prefix (`secret/data` is a prefix of `secret/data/payments/*`) and
returns the override's scope, ignoring the `payments/` part. The proposed grant is
`secrets.read` on the whole environment, which also holds
`mobile-app-firebase-server_key`. The solver's witness is `read secret/data/<any name
outside payments/>`. Vault denies it, and Keyorix allows it. The Kubernetes role
`deployer` (`mobile-readwrite`) is worse: `secrets.write` on the same environment lets
it overwrite `payments-db-password`.

The demo's own step-6 equivalence check does not catch this. It compares
`basename(leaf)` (`firebase`) with the imported Keyorix names, but the importer names a
multi-field secret `<path>-<field>` (`mobile-app-firebase-server_key`). No name ever
matches, the "Keyorix has it, Vault denies it" branch never runs, and the check prints
PASS on every run.

Two more classes come from the same root, a Keyorix scope coarser than the Vault path
selector. The solver reports both:

- `Resolve` with the default convention uses only the first two segments
  (`<project>/<environment>`) and ignores the rest. An exact path
  (`secret/data/payments/prod/db-password`) becomes read on the whole environment.
  `TestBuildPolicyItems_ExactReadGrant` currently asserts that outcome as correct.
- A `metadata/` policy is stripped to the same scope as a `data/` one. A browse-only
  policy (`list` on `secret/metadata/team-a/*`, the usual Vault UI pattern) becomes
  `secrets.read`, which includes the values.

The lowest-severity class affects every real case that grants anything: `secrets.read`
includes listing names and reading metadata and versions, which Vault controls
separately under `metadata/`. A KV v2 policy on `data/*` alone cannot list, but the
migrated grant can.

## New vs. state of the art

- Policy verification with SMT is established for cloud IAM: AWS Zelkova (SMT over
  IAM/S3 policies, used by IAM Access Analyzer) and its successors decide "can this
  policy allow X" and policy-vs-policy comparison. Academic work covers XACML and
  firewall equivalence. None we know of targets HashiCorp Vault/OpenBao ACL semantics
  (priority matching with `+`/`*`, same-path merge, KV v2's data/metadata split).
- What is new here is checking a **migration** between two authorization models with
  different shapes: path-glob ACLs on one side, project/environment-scoped RBAC on the
  other. The question is cross-model containment of the translated policy, not
  analysis of one policy, and the inputs are generated from the translator's own code
  so the proof tracks the shipped mapping.
- The split encoding (exact partition by import run and operation, plus static rule
  slicing by literal prefix) is a standard technique. Its value is practical: it is what
  takes this domain from "a few dozen rules" to the size of real Vault deployments.

## Technical risks

- **Semantic fidelity to Vault.** The proof is only as good as the model of Vault's rule
  selection. It is tested against Vault's documented rules and is self-consistent
  (differential, mutation, two solvers), but it has not yet been compared with a
  running Vault (`vault_oracle.py`, pending e2e VM). Known gaps: `capabilities-self`
  may treat the `list` trailing-slash case differently from a real `LIST`; whether `+`
  matches an empty segment is assumed, not verified.
- **Not modelled**: Sentinel/EGP, templated paths (treated as literal, so they match
  nothing), `allowed_parameters`/`denied_parameters`, wrapping TTLs, `patch`, `sudo`
  (Unmappable upstream), namespaces, non-KV engines (database, PKI, transit), Keyorix
  secret sharing/ACL entries, and native Keyorix secrets that never came from Vault (a
  grant on a shared environment also reaches those; the spike does not count that).
- **The import model is an input.** Which Vault prefix went to which project/environment
  is recorded per case from the scripts. A real tool must read it from the
  migration's own provenance (`migrate.source-id`), or the proof checks a hypothetical
  import.
- **Solver performance is shape-dependent.** The single-query encoding degrades sharply.
  The split encoding stayed fast across the tested sizes and shapes, but `+`-heavy
  policies make larger regular-expression intersections, and string solving has no
  general complexity guarantee. A production check needs a per-part timeout that
  reports "unknown" loudly. It must never report "subset".
- **Toolchain.** z3/cvc5 are not in CI or in the product. The Go golden test runs in CI;
  the solver tests do not. Shipping this as a migration gate means either a solver
  dependency in `keyorix-migrate` (cgo or a subprocess) or a pure-Go decision procedure
  for this restricted fragment. The fragment (prefix and segment globs over one name)
  may be decidable with automata directly, without a general SMT solver. That is a
  follow-up question.

## Verdict

**Works with limits.** The solver decides the subset question for all 10 cases. On real
seeded policies it found genuine widenings that the existing sampling checks miss,
including one where the existing check passes vacuously. The split encoding keeps it
fast at the tested sizes. The limits are fidelity to Vault (pending a live-Vault
comparison), the unmodelled features listed above, and the solver dependency.
