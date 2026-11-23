# devtools/vacuum

The OpenAPI linter for the `openapi-lint` CI job (`.github/workflows/ci.yml`) and
`make openapi-lint`: [vacuum](https://github.com/daveshanley/vacuum) (MIT), run with the
ruleset in the repository root's `.vacuum.yaml` against `server/http/handlers/openapi.yaml`.

- `VACUUM.pin`: the pinned release and the SHA-256 of its archive for each OS/arch the
  runners and developers use.
- `install.sh`: downloads that archive from the GitHub release, refuses it unless its
  SHA-256 equals the pin, and installs the binary at `.cache/vacuum/vacuum`.
- `canary-bad.yaml`: a deliberately broken spec. CI fails if vacuum accepts it, which
  proves the ruleset is loaded and its error rules fire.

## Taking a new vacuum version

A new vacuum release can change the findings: a new rule, or a fix that makes an
existing `.vacuum.yaml` line take effect. So treat a bump like a ruleset edit. Download
the candidate's archives and its `checksums.txt`. Check each archive against
`checksums.txt` and against the release page's asset digest. Then run the old and the
new binary over `server/http/handlers/openapi.yaml` and `canary-bad.yaml` with the same
`.vacuum.yaml`: `vacuum spectral-report` writes the findings as JSON, and
`vacuum lint --show-rules` lists the rules that run. Take the version only if the
error set is the same and every new warning is explained. Then change `version=` and
every `sha256_<os>_<arch>=` line in `VACUUM.pin` in one commit, and say in the PR what
the comparison showed. `install.sh` refuses an archive whose hash is wrong or missing,
so a half-updated pin fails CI instead of installing an unchecked binary.
