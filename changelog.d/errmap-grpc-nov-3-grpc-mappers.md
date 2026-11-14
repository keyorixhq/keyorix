### Fixed
- **A grant-ceiling refusal on `POST /invitations` (global invite) is 403, not 500 (#4154).** `CreateGlobalInvitation` answered core's `ErrPermissionDenied` ("a role the actor cannot grant") with the generic 500 once past its two pre-checks; it now answers 403 like the other grant routes. `TestEveryGrantRouteMapsTheCeilingRefusalTo403` drives the four routes the guard had listed as exempt or missing (project invite, global invite, access-request approval, membership activation).
- **gRPC answers a typed storage read fault as `Unavailable` + `storage_unavailable` from the role, group, project, share and secret-ACL mappers (was `Internal`).** REST has answered 503 for the same fault since #4077. The user, machine and dynamic-secret mappers already did. A transient authorization-storage fault under a group RPC is `Unavailable` with the gates' fixed text.

### Internal
- **The eight gRPC family mappers (`mapRoleError`, `mapMachineError`, `mapUserError`, `mapProjectError`, `mapShareError`, `mapDynamicError`, `mapSecretACLError`, `groupError`) answer through the shared `coreErrorStatus` adapter.** Every current gRPC code and client text is kept, apart from the storage-fault change above and the codes the classifier now answers where the old default was `Internal` (a validation sentinel, a not-found of another entity). `ErrBuiltinRole` stays `FailedPrecondition` on gRPC while REST answers 403 (ask `errmap-grpc-builtin-role-code`). `TestFamilyMappers_*` pins the shared storage-fault and refusal answers on all eight.
- **One derivation of the granting set.** `TestEveryGrantingServiceMapsPermissionDenied` reads `internal/core/testdata/grant_ceiling_reaching_methods.txt`, the file the REST guard uses; `guardrules.GrantCeilingMethods` is deleted.

### Testing
- **The 15 project-scoped legacy-role fixtures in `server/grpc/**` grant project roles** (`project_developer`, `project_viewer`, `project_admin`) instead of the install-wide editor/viewer/admin/super_admin.
