### Changed
- **Documented why identity folding uses NFC, not NFKC.** `internal/identity`
  now states that compatibility variants (fullwidth letters, ligatures, roman
  numerals) are distinct principals by design, and that SSO/SCIM mapping must
  fold or reject at its own boundary. A test pins the behaviour. No runtime
  change.
