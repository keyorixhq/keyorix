### Added
- Nightly strict-gate workflow for `FuzzOpenAPIStateful` (`.github/workflows/openapi-strict-nightly.yml`): runs the stateful OpenAPI fuzzer with `KEYORIX_OSF_STRICT=1` at 08:43 UTC, making any undeclared 5xx on a well-formed request fatal the morning after it lands rather than silent in the candidate list. Already-triaged bugs are waived by `osKnownUndeclared5xx` (#4132).
