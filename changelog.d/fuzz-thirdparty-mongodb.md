### Added
- **Hostile-server fuzz harness for the MongoDB driver.** `fuzz/thirdparty/mongodb` drives
  `mongo-driver/v2`, the client behind the dynamic-secrets and rotation MongoDB connectors,
  against a fake server that replies with hostile OP_MSG/OP_REPLY and BSON bytes, and checks
  that the client returns an error instead of panicking, hanging or exhausting memory.
