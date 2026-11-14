### Testing
- Fixed a memory leak in the fault-injection fuzz world fixture: a freshly built
  world's last-used bookkeeping timer kept the whole core graph (and its database
  schema cache) alive after the world was torn down, so long fuzz runs grew
  resident memory without bound. The fixture now quiesces that bookkeeping at
  teardown, and a new gate asserts a torn-down world retains no significant heap.
