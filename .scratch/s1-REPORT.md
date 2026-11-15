# S1 — "an issuer cannot widen" sweep — REPORT

**Report location note.** The requested path `/mnt/data/wave4/out/s1-REPORT.md`
is NOT writable from this sandboxed session (the harness confines filesystem
writes to the working directory `/mnt/data/wave4/s1`). Per the runtime fallback
rule this report lives at `.scratch/s1-REPORT.md`, committed on the branch with
`git add -f` (`.scratch/` is gitignored). The committed sweep table is at
`docs/findings/2026-11-15-issuer-cannot-widen-sweep.md`.

**Environment note.** The package-temperature sensor
(`/sys/.../hwmon2/temp1_input`) is also outside the working directory and
unreadable from this sandbox, so thermal load is managed structurally instead:
`nice -n 10`, `-p 2 -parallel 2` on every Go command. Go module/build caches
could not be pointed at `/mnt/data/wave4/{gocache,gomod}` (outside the working
dir); the toolchain's own configured caches are used.

**Most reasonable reading (nobody answers questions).** "Widen" = the minted or
granted artefact carries permissions/scope/lifetime the actor does not hold, OR
it sheds a confinement (PAT/machine restriction: permission allowlist,
project/env scope, CIDR, expiry) that bound the actor.

---

## Executive summary (updated as results arrive)

This branch inherits a mature, machine-checked enforcement surface. Two spines
already carry almost the entire property:

- **Grant ceiling** (`requireGranterHoldsRolePermissions` family): every
  role-grant path routes through it, it calls `Authorize` per bundled
  permission, and `Authorize` intersects the PAT restriction. So "a restricted
  PAT grants a role beyond its restriction" is closed for free on every gated
  grant path. A guard (`GrantCeilingMethods` + `TestEveryGrantingServiceMaps…`)
  keeps the transport mapping honest.
- **Restricted-PAT deny-by-default** (`restrictedPATUngatedWrites`): any write
  that bypasses `Authorize` must declare a policy; AST guards fail closed on an
  undeclared ungated write. This is the net that catches a mint path like PAT
  creation, break-glass and (the #4332 case) machine-token issue.

The #4332 defect class — a *permission-gated* mint whose *artefact* escapes the
actor's PAT restriction even though the issuance check passed — is the one place
the two spines do not automatically meet. The sweep's job is to find any other
mint path in that seam.

### Findings so far

(To be filled as verification completes. Preliminary: most GOAL paths are
ENFORCED through the grant ceiling; the candidates still open are
`CreateMachineIdentity`, `AssignPermissionToRole`/`CreateRole` (#169 definition
ceiling), `RefreshSession`, `IssueSetupToken` reachability, and SAML/OIDC/SCIM
provisioning / group→role mapping.)

---

## What is committed / what has run

- `docs/findings/2026-11-15-issuer-cannot-widen-sweep.md` — the sweep table.
- This report.

Tests run: (recorded here as they execute, with SHAs).

---

## Per-oracle "what it does NOT verify"

- **The grant ceiling via `Authorize`** verifies the actor holds each bundled
  permission at the grant scope, intersected with any PAT restriction. It does
  NOT verify anything about the *target principal's* identity confinement, and
  it is a mint-time check only (a later loss of authority does not retro-revoke;
  see INV-CORE-machine-token-issue-cannot-widen-caller "Mint-time ceiling only").
- **`requireMachinePrivilegeCeiling` / `requireActorHoldsTargetPermissions`**
  checks the caller holds every permission the target machine holds at each of
  the target's scopes; it does NOT check the caller's credential *expiry* (an
  unrestricted-but-expiring credential can still mint a non-expiring token for a
  fully-covered peer — documented "Not covered" in the INVARIANT), and does not
  re-check at use time.
- **`restrictedPATUngatedWrites` AST guards** verify that every ungated write has
  a declared policy; they do NOT verify that a *gated* write's `Authorize` call
  actually names the right permission/scope — that is the authzdiff harness's job
  and is itself bounded to the seeded fixtures.

(Expanded per-path below as each row is resolved.)

---

## Talk material

(Completed in the final report.)
