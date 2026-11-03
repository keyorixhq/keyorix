### Changed

- Test coverage: the first-admin bootstrap now has a two-dialect test proving that a concurrent writer taking the same username answers "user already exists" (no raw constraint text) and leaves nothing seeded. The rename, SCIM, SSO and bootstrap username mappings themselves shipped in #3822.
