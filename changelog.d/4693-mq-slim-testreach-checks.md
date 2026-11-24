### Testing

- Merge-queue slimming: `MQ_SLIM_TESTREACH_CHECKS` narrows an enforced testreach lever to the named unsharded checks (for example `test-suite/root-1,test-suite/root-2`). A list that names a sharded leg (`http-2`, `server-3`, ...) is refused whole and testreach enforces nothing, because a sharded package's narrowed tests run only on its first shard.
