### Fixed

- `audit search --actor <name>` (`GET /api/v1/audit/search?actor=`) now also matches machine identities: a partial, case-insensitive name such as `payments-ci`, `PAYMENTS` or `ci` finds the rows the ACTOR column shows under that name, not only user names (#3736).
- The `break_glass.activated` and `break_glass.revoked` audit descriptions name the user the way `role.assigned` does (`user 2 ("dana")`), not only `user 2`; when the name cannot be read they keep the bare id (#3741).
