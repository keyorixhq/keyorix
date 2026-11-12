### Testing
- **Secret-leak canary oracle.** A sweep over every HTTP route and unary gRPC method, plus a CLI test that builds the real binary, plants secret-class canaries and fails if one appears on a response, log, stdout, stderr, metrics, DB cell, raw DB file or temp file. Allowed hits are an exact route, label and surface list that fails when a row goes unused.
