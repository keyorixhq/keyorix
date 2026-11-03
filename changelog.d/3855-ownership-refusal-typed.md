### Fixed

- A refused secret-ownership transfer by a non-owner now matches `core.ErrPermissionDenied` at its call site, so the nightly `rollout` guard `TestEveryErrorPermissionDeniedRefusalIsTyped` is green in enforce mode. The refusal text and its HTTP/gRPC mapping are unchanged.
