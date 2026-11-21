### Internal
- **Seven open code-scanning warnings in test/e2e tooling closed in code.** `scripts/e2e/sdkdiff` and `scripts/e2e/livereplay` refuse a non-loopback target and keep redirects on loopback; the sdkdiff shim decode, `hostile.ParseJSON` (new `MaxParseJSONBytes`) and the web drift guard's `proseMissing` no longer read unbounded input or build a regexp from data.

### Documentation
- `docs/security/security-txt.md` states that nothing in this repository serves `security.txt` and lists the steps to publish it at `/.well-known/security.txt` on the website.
