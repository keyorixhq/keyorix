### Fixed
- **gRPC: a canceled request is `Unavailable`, not `Internal`.** The family mappers (`mapRoleError`, `mapUserError`, `groupError`, `mapProjectError`, `mapMachineError`, `mapShareError`, `mapDynamicError`, `mapSecretACLError`) passed `context.Background()` to the shared classifier, so a request whose context was canceled while a core call ran was not recognised as an authorize outage and answered `Internal` where REST answers 503. They now take the RPC ctx. `mapSecretError` (and the share scope resolver's read errors) answer through the same classifier, so a secret RPC's audit or storage outage is `Unavailable` too; codes and client texts are unchanged.

### Testing
- **Test-helper guard.** `RBACTestHelper.AssignUserRole` / `AssignGroupRole` refuse a global-only role (the legacy `super_admin`/`admin`/`editor`/`viewer`/`auditor`, the `system_*` roles) at a project scope, which core refuses too (#3605); a fixture that did it tested a grant no install can hold.
- **Audit-outage mapping guard** flags a gRPC mapper that takes a `context.Context` and calls `context.Background()`/`TODO()` (`INV-GRPCSVC-mapper-takes-rpc-ctx`); its calibration has red and green cases.
