# Server binary size: measurement, composition, and the cloud-SDK question

Measured 2026-08-29. Answers three questions raised by Keyorix's "lightweight
alternative" positioning against Vault/OpenBao and CyberArk Conjur: (1) did the
G80 campaign's ~176 deleted methods and the deleted remote-topology / MFA-purge
code move the server binary's size, (2) where does the size actually come
from, and (3) do cloud provider SDKs (the thing OpenBao is externalizing
plugins specifically to remove) link into the shipped server binary.

## Method (reproduce this exactly, or the comparison is meaningless)

- Toolchain: `go1.26.6` for every row, pinned via `GOTOOLCHAIN=go1.26.6`
  regardless of the checkout's local Go toolchain — this matches
  `.github/workflows/release.yml`'s `actions/setup-go` pin. All four
  commits below declare `go 1.26.6` in `go.mod`/`go.work`, so no cross-version
  skew is being measured.
- Target: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`, matching the `release`
  target in the root `Makefile` (the same one `make release` cross-compiles
  for the GitHub Release upload) and matching Vault's own "Linux amd64"
  size reports below.
- Flags: `-trimpath` plus the exact `$(LDFLAGS)` the Makefile's `release`
  target uses, with `VERSION=v0.0.0-sizetest` and `GIT_COMMIT=0000000` fixed
  identically across all four builds (so the injected `-X` string lengths
  don't perturb size) and `TRUST_UPDATE_KEYS`/`TRUST_LICENSE_KEYS` left empty
  (the release default without real signing keys baked in).
- Web UI: the release binary embeds the built dashboard
  (`server/webui/embed.go`, ADR-070). Each row ran `pnpm --dir web install
  --frozen-lockfile && pnpm --dir web build` from that commit's own source
  and copied the real `web/dist/` into `server/webui/dist/` before building
  — not the committed placeholder `index.html`, which is what a plain
  `go build ./server` would embed instead of what actually ships.
- Stripped variant: same build with `-s -w` added to `-ldflags`. The
  Makefile's release build does **not** pass `-s -w` today, so "unstripped"
  is what actually ships; "stripped" is reported alongside because one of
  Vault's own size regressions (below) turned out to be exactly this knob.
- One worktree, one tag/commit checked out at a time, `git checkout --
  server/webui/dist/index.html` to restore the placeholder between builds.

## Task 1 — the four-row table

| Ref | Commit | Unstripped | Stripped (`-s -w`) |
|---|---|---|---|
| `g80-pre-remediation` | `45ae4bbe` | 99,942,787 B (95.31 MiB) | 71,839,906 B (68.51 MiB) |
| `pre-remote-topology-deletion` | `a08f70aa` | 99,953,637 B (95.32 MiB) | 71,848,098 B (68.52 MiB) |
| `pre-1593-mfa-purge-deletion` | `5eea778e` | 99,933,063 B (95.30 MiB) | 71,831,714 B (68.50 MiB) |
| `main` (current) | `9ef802a3` | 99,923,544 B (95.29 MiB) | 71,823,522 B (68.50 MiB) |

Net change, `g80-pre-remediation` → `main`: **-19,243 bytes unstripped
(-0.019%), -16,384 bytes stripped (-0.023%)**. The size moves up and down by
single-digit KB between intermediate points, consistent with alignment/padding
noise from small code churn, not a trend.

**The campaign's ~176 deleted methods and the deleted remote-topology and
MFA-purge code did not move the binary size in any measurable way.** This is
the expected result, not a surprising one: Go's linker already performs dead
code elimination, so methods with zero callers were already excluded from the
binary before they were deleted from the source. Deleting already-unreachable
code cleans up the source tree and the attack surface (fewer methods to
misuse, audit, or accidentally wire up) — it was never going to be a binary
size lever, and treating it as one would have been the wrong hypothesis to
chase. The size story, if there is one, lives entirely in what's linked in
today, not in what the campaign removed.

## Task 2 — where the size actually comes from

`go tool nm -size` on the unstripped `main` binary reports **99.9 MB of file
on disk**, but nm's own totals split almost evenly between two very different
things:

| nm type | Bytes | Meaning |
|---|---|---|
| `T` (text/code) | 34,074,623 (46.6%) | Actual on-disk instructions |
| `B` (BSS) | 33,930,014 (46.4%) | **Zero-filled runtime memory — reserved at load time, not present in the file** |
| `r`/`R` (rodata) | 4,465,071 (6.1%) | On-disk constant data |
| `D`/`d` (data) | 690,709 (0.9%) | On-disk initialized data |

The single largest nm symbol by far is `crypto/internal/fips140/drbg.memory`
at exactly 33,554,432 bytes (32 MiB) — but it's type `B`. It's Go's stdlib
FIPS-140 DRBG's pre-allocated entropy pool, reserved as zeroed virtual memory
the first time it's touched at runtime; it does not add a single byte to the
file that ships. Attributing it to "binary size" would have been a wrong
conclusion reached by trusting a single number without checking what it
actually measures — worth flagging explicitly since it's exactly the kind of
mistake this exercise was designed to avoid, not just an aside.

Excluding BSS, here's what the remaining ~39.2 MB of nm-attributable on-disk
symbol bytes breaks down to by dependency family (the true on-disk total is
~99.9 MB; the gap is DWARF debug info, the symbol table itself, and
`pclntab`/runtime function metadata, none of which `nm` attributes to a
package):

| Dependency family | On-disk bytes | % of nm-attributable total |
|---|---|---|
| **AWS SDK v2 (all services)** | 9,483,079 | 24.17% |
| keyorix own code | 3,488,522 | 8.89% |
| redis go-redis client | 3,496,456 | 8.91% |
| modernc.org sqlite (pure-Go driver) | 2,006,130 | 5.11% |
| jackc/pgx (Postgres driver) | 1,310,653 | 3.34% |
| Go stdlib `crypto/*` | 1,256,309 | 3.20% |
| mongo-driver | 1,159,020 | 2.95% |
| protobuf runtime | 889,257 | 2.27% |
| grpc | 708,408 | 1.81% |
| **Azure SDK + MSAL** | 658,030 | 1.68% |
| **GCP google-api-go-client** | 637,772 | 1.63% |
| Go stdlib `net`/`net/http` | 846,259 | 2.16% |

**Cloud provider SDKs (AWS + Azure + GCP) together: 10,778,881 bytes — about
10.8% of the current 99.9 MB server binary.** That is a real, load-bearing
line item, not noise — comparable in weight to the AWS SDK alone being nearly
3x the size of Keyorix's own application code.

## Task 3 — do cloud SDKs link into the server binary, and why

Yes — but **not for the reason the hypothesis in this task assumed.**

`internal/cli/secret/source_azure.go` and `source_gcp.go` (the Vault-migration
importer) are **not reachable from the server binary at all**:
`go list -deps ./server` contains zero packages under
`github.com/keyorixhq/keyorix/internal/cli` (verified: `grep -c
"keyorixhq/keyorix/internal/cli" <deps list>` → `0`). The only file under
`server/` or `cmd/` that references `internal/cli/secret` is
`server/http/remote_storage_g80_secret_update_test.go` — a `_test.go` file,
excluded from every production build. `build-cli` (`.`) and `build-server`
(`./server`) have been two separate binaries since before this campaign
(Makefile `build-cli`/`build-server` targets), and the importer's cloud-SDK
imports live entirely on the CLI side of that split already.

**The cloud SDKs are in the server binary because of separate, legitimate,
already-shipped server features** — not the importer. Each provider has the
same four-shape pattern:

| Provider | Connect source | KMS auto-unseal | Dynamic secrets engine | Rotation |
|---|---|---|---|---|
| AWS | `internal/connect/awssm.go` | `internal/crypto/awskms/awskms.go` | `internal/dynamic/awssts.go` | `internal/rotation/awsiam.go` |
| Azure | `internal/connect/azurekv.go` | `internal/crypto/azurekms/azurekms.go` | `internal/dynamic/azure.go` | `internal/rotation/azure.go` |
| GCP | — | — | `internal/dynamic/gcp.go` | `internal/rotation/gcpsa.go` |

(AWS also uniquely pulls in `internal/evidencesink/objectstore.go`, an S3
compliance-evidence sink.) Every one of these is reachable from
`./server` today and is why `go tool nm` finds AWS/Azure/GCP symbols in the
binary regardless of whether anyone ever imports secrets from Vault.

## Task 4 — the verdict

**A build tag excluding the importer from the server build would save
approximately zero bytes**, because the importer was never linked into the
server binary to begin with — there is nothing to exclude. The task's
proposed narrow fix doesn't apply to what was actually found; applying it
would be solving a problem that doesn't exist while leaving the real one
(10.8 MB of cloud SDKs, ~10.8% of the binary) untouched.

The real 10.8 MB is not accidental or dead weight — it backs product features
(KMS auto-unseal, dynamic secrets engines, secret rotation, connect sources)
that are part of what Keyorix ships and that some deployments genuinely use.
Shrinking it for real would mean making those provider integrations optional
at build time — i.e., closer to the plugin architecture OpenBao is building
(see ADR-038 pluggable-key-providers and ADR-041 kms-key-provider for the
existing internal architecture this would extend). That is exactly the
complexity this task's own brief said not to reach for before customers ask
for it: a real plugin/build-variant split touches the release pipeline
(`make release`'s 8-way cross-compile, SBOM generation per binary,
`checksums.txt`, cosign signing) for a currently-hypothetical need.

**Recommendation: no code change.** File the 10.8 MB figure as a known,
measured, and understood quantity — not a bug, not urgent — and revisit only
if/when a customer conversation or competitive pressure specifically turns on
"why is AWS/Azure/GCP SDK code in a binary I run air-gapped with none of
those backends configured." At that point the real options are (a) Go build
tags per provider integration (four provider-specific server binaries, or
one binary per provider-subset a customer actually needs) or (b) true runtime
plugins (Hashicorp go-plugin style, matching OpenBao). Both are bigger than a
one-line Makefile change and both belong in an ADR with sign-off before any
implementation, not a quiet follow-up to this measurement.

## What Keyorix's number is, and isn't, being compared to

**Keyorix `keyorix-server`, linux/amd64, this repo's own release build
(unstripped): 99,923,544 bytes (95.29 MiB) at `main` as of 2026-08-29.**
This binary bundles the full server (HTTP + gRPC APIs), the embedded web
dashboard, every secrets engine and dynamic-secrets backend, every KMS
auto-unseal provider, every rotation backend, and every connect source. It
does **not** include the CLI (`keyorix`, a separate binary) or the Vault-
migration importer (CLI-only, per Task 3).

| Product | Reported size | What's included | Source |
|---|---|---|---|
| **Keyorix** `keyorix-server` (linux/amd64) | 95.29 MiB (99,923,544 B) | Server + gRPC + embedded web UI + all secrets engines/KMS/rotation/connect backends. Excludes CLI. | This measurement, method above. |
| **Vault** (linux amd64) 1.14.2 | 355 MB | One binary: server, agent, CLI, and every bundled secrets engine. | [hashicorp/vault#22893](https://github.com/hashicorp/vault/issues/22893) — 247 MB (1.14.1) → 355 MB (1.14.2), +44%, open, no maintainer-confirmed root cause ("I don't see a rational explanation for this"). |
| **Vault** (linux amd64) 1.13.3 | 246 MB | Same, one binary. | [hashicorp/vault#21069](https://github.com/hashicorp/vault/issues/21069) — 178,626,560 B (1.13.2) → 245,846,544 B (1.13.3), +37%, open; reporter attributes the jump to unstripped debug symbols (same class of confound this doc's stripped/unstripped columns exist to catch). |
| **OpenBao** plugin externalization rationale | not yet quantified upstream | Rationale for moving cloud-provider integrations out of the core binary into external plugins. | [openbao/openbao discussion #64](https://github.com/orgs/openbao/discussions/64) — maintainer @cipherboy, 2024-01-25: *"the Azure SDK and other cloud provider SDKs can be removed as a dependency, which greatly contributed to binary size."* |
| **CyberArk Conjur Enterprise** | N/A (not a single binary) | One appliance container: nginx + 2 PostgreSQL instances (config/secrets + audit) + the Conjur appliance + syslog-ng. Production requirement: 4 cores / 8 GB RAM / 50 GB disk. | [CyberArk Conjur architecture overview](https://www.msbiro.net/posts/cyberark-conjur-architecture-system-requirements/), citing CyberArk's official system-requirements docs. |

**Comparing Keyorix's 95.29 MiB directly to Vault's 355 MB "one binary does
everything" figure is the apples-to-oranges claim this document exists to
prevent.** Vault's number bundles server + agent + CLI + all engines in one
artifact; Keyorix's number is the server binary only, with the CLI built and
shipped as a second, separate artifact (`keyorix`). If the CLI's own size
needs quoting alongside this number for a fair "everything a user downloads"
comparison, that's a separate measurement this document doesn't include —
flagging it here rather than silently presenting a partial number as if it
were the full one. Conjur isn't a single binary at all, so the fairest
comparison to Keyorix there is qualitative (footprint/RAM/services running),
not a byte-for-byte one.

## Reproducing this measurement

```
git checkout --detach <ref>
GOTOOLCHAIN=go1.26.6 pnpm --dir web install --frozen-lockfile
GOTOOLCHAIN=go1.26.6 pnpm --dir web build
rm -rf server/webui/dist && mkdir -p server/webui/dist
cp -R web/dist/. server/webui/dist/
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=go1.26.6 go build \
  -ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=v0.0.0-sizetest \
            -X github.com/keyorixhq/keyorix/internal/version.Version=v0.0.0-sizetest \
            -X github.com/keyorixhq/keyorix/internal/version.Commit=0000000 \
            -X github.com/keyorixhq/keyorix/internal/trust.updateKeysB64= \
            -X github.com/keyorixhq/keyorix/internal/trust.licenseKeysB64=" \
  -trimpath -o keyorix-server_linux_amd64 ./server
git checkout -- server/webui/dist/index.html
```

Add `-s -w` to `-ldflags` for the stripped variant. Composition analysis:
`go tool nm -size keyorix-server_linux_amd64`, filter out `B`/`b` type rows
before attributing bytes to a package (see Task 2's methodology note above).
