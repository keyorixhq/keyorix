### Fixed
- **Machine callers can issue machine tokens.** A machine identity holding `roles.assign` at a project can now issue a token for another machine in that project over REST and gRPC. Before, the privilege ceiling was checked as user 0, so the call was always refused, and REST answered 500. A ceiling refusal now answers 403 (gRPC `PermissionDenied`).

### Security
- **Machine token issuance cannot widen the caller's own credential.** A machine caller may not issue a token for itself. It is also refused when its own credential carries a CIDR allowlist or is a federated OIDC/Kubernetes JWT, so a confined or short-lived credential cannot mint an unrestricted, durable `kx_machine_` token (the machine counterpart of the restricted-PAT rule). A machine caller is also refused a target whose role is admin-tier by name or permission bundle, not only by the admin-bypass flag.
