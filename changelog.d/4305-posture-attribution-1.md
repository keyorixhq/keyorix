### Changed
- `admin validate --posture` no longer labels a weakening "explicit" when the config file only wrote the *other* side of a per-listener or per-channel setting. A file that enables rate limiting for HTTP and says nothing about gRPC, sets only the HTTP `metrics_token`, secures only one of the two SMTP `tls` keys, or pins a Shamir commitment on the primary key provider but not on a fallback now reports the silent side as `shipped-default` (#2895).

### Testing
- Every deprecated `insecure_` alias is now tested for all three origin cases in the posture report: old name written (explicit), nothing written (shipped default), both written (explicit) (#2925).
- A guard fails if a registry entry that reads more than one config key is neither narrowed to its weak side nor exempted with a reason.
