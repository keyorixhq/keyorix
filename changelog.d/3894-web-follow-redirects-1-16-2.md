### Fixed
- **The web `Audit dependencies` CI step passes again.** `follow-redirects` 1.16.1 (pulled in by `axios`) is flagged by GHSA-mrwp-f3q8-3g9p (custom credentials can follow redirects), patched in 1.16.2. `web/pnpm-workspace.yaml` now overrides the vulnerable range to `^1.16.2` and the lockfile resolves to the patched version.
