### Testing
- Added slow-disk fault coverage for key-material durable writes: a new test
  injects a bounded delay at the KEK-rotation directory fsync and verifies the
  rotation still commits atomically and the store reopens and recovers its key,
  while measuring that the slow fsync is held under the key-manager lock (an
  availability characterization of rotation under a degraded disk).
- Fixed a memory leak in the fault-injection fuzz world fixture: a freshly built
  world's last-used bookkeeping timer kept the whole core graph (and its database
  schema cache) alive after the world was torn down, so long fuzz runs grew
  resident memory without bound. The fixture now quiesces that bookkeeping at
  teardown, and a new gate asserts a torn-down world retains no significant heap.
