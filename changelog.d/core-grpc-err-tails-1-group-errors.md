### Testing

- gRPC group RPCs: a test now pins that a storage fault whose text says "not found" still answers `Internal` with the static message, never `NotFound`, through the real handlers (GetGroup, UpdateGroup, DeleteGroup, AddGroupMember). The missing-group `NotFound` case, the SCIM Groups member-read 500 and the lost invitation-accept race (account removed) were already fixed and tested on main.
