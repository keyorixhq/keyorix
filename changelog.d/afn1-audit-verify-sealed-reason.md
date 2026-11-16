### Fixed
- **`GET /api/v1/audit/verify` for a sealed chain now carries a non-empty `reason`.** Status `sealed` already returned the seal text in `state_reason`; `reason` was absent (it was only set for `broken`), so a client that renders `reason` printed an empty one (#4230). `reason` now repeats the seal text; `first_broken_id` stays absent for a sealed chain.
