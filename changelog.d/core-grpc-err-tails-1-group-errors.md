### Fixed

- gRPC group RPCs: a missing group answers `NotFound` and a storage fault answers `Internal` with the static message; both are now pinned through the real handlers (GetGroup, UpdateGroup, DeleteGroup, AddGroupMember). The SCIM Groups member-read 500 and the lost invitation-accept race (account removed) were already fixed on main and have tests there.
