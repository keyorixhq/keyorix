### Internal
- **Claude Code no longer appends AI attribution in this repo.** `.claude/settings.json` sets `attribution.commit` and `attribution.pr` to empty strings, `attribution.sessionUrl` to `false` and the deprecated `includeCoAuthoredBy` to `false`, so sessions run from a clone stop adding the trailers and footers that fail the `no-attribution` check.
