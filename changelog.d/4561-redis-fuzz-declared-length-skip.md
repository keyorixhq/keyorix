### Testing
- **FuzzRedisReply skips oversized declared RESP lengths.** Inputs whose length header (at any byte offset, including after a bulk-body desync) exceeds an allowance are skipped instead of exhausting the rig's memory; the go-redis behaviour is recorded by a log-only characterisation test.
